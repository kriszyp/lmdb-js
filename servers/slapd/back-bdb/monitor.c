/* monitor.c - monitor bdb backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2006 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/stdlib.h>
#include <ac/errno.h>
#include <sys/stat.h>
#include "lutil.h"
#include "back-bdb.h"
#include "../back-monitor/back-monitor.h"

static ObjectClass		*oc_olmBDBDatabase;

static AttributeDescription	*ad_olmBDBCounter;

static int
bdb_monitor_update(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	struct bdb_info		*bdb = (struct bdb_info *) priv;
	Attribute		*a;

	/* NOTE: dummy code that increments a olmBDBCounter
	 * any time it's called; replace with something useful */
	unsigned long		u;
	char			buf[ BUFSIZ ];
	struct berval		bv;

	assert( ad_olmBDBCounter != NULL );

	a = attr_find( e->e_attrs, ad_olmBDBCounter );
	assert( a != NULL );
	lutil_atoul( &u, a->a_vals[ 0 ].bv_val );
	u++;
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%lu", u );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );
	
	return SLAP_CB_CONTINUE;
}

static int
bdb_monitor_modify(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	struct bdb_info		*bdb = (struct bdb_info *) priv;
	
	return SLAP_CB_CONTINUE;
}

static int
bdb_monitor_free(
	Entry		*e,
	void		*priv )
{
	struct bdb_info		*bdb = (struct bdb_info *) priv;
	
	return SLAP_CB_CONTINUE;
}

/*
 * NOTE: there's some confusion in monitor OID arc;
 * by now, let's consider:
 * 
 * Subsystems monitor attributes	1.3.6.1.4.1.4203.666.1.55.0
 * Databases monitor attributes		1.3.6.1.4.1.4203.666.1.55.0.1
 * BDB database monitor attributes	1.3.6.1.4.1.4203.666.1.55.0.1.1
 *
 * Subsystems monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0
 * Databases monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0.1
 * BDB database monitor objectclasses	1.3.6.1.4.1.4203.666.3.16.0.1.1
 */
#define	BDB_MONITOR_SCHEMA_AD		"1.3.6.1.4.1.4203.666.1.55.0.1.1"
#define	BDB_MONITOR_SCHEMA_OC		"1.3.6.1.4.1.4203.666.3.16.0.1.1"

static struct {
	char			*name;
	char			*desc;
	AttributeDescription	**ad;
}		s_at[] = {
	{ "olmBDBCounter", "( " BDB_MONITOR_SCHEMA_AD ".0 "
		"NAME ( 'olmBDBCounter' ) "
		"DESC 'A dummy counter' "
		"SUP monitorCounter "
		"NO-USER-MODIFICATION "
		"USAGE directoryOperation )",
		&ad_olmBDBCounter },

	{ NULL }
};

static struct {
	char		*name;
	char		*desc;
	ObjectClass	**oc;
}		s_oc[] = {
	{ "olmBDBDatabase", "( " BDB_MONITOR_SCHEMA_OC ".1 "
		"NAME ( 'olmBDBDatabase' ) "
		"SUP monitoredObject STRUCTURAL "
		"MAY ( "
			"olmBDBCounter "
			") )",
		&oc_olmBDBDatabase },

	{ NULL }
};

/*
 * call from within bdb_initialize()
 */
int
bdb_monitor_initialize( void )
{
	int		i, code;
	const char	*err;

	static int	bdb_monitor_initialized = 0;

	/* register schema here; if compiled as dynamic object,
	 * must be loaded __after__ back_monitor.la */

	if ( bdb_monitor_initialized++ ) {
		return 0;
	}

	for ( i = 0; s_at[ i ].name != NULL; i++ ) {
		LDAPAttributeType	*at;

		at = ldap_str2attributetype( s_at[ i ].desc,
			&code, &err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !at ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"AttributeType load failed: %s %s\n",
				ldap_scherr2str( code ), err, 0 );
			return LDAP_INVALID_SYNTAX;
		}

		code = at_add( at, 0, NULL, &err );
		if ( code != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"AttributeType load failed: %s %s\n",
				scherr2str( code ), err, 0 );
			code = LDAP_INVALID_SYNTAX;
			goto done_at;
		}

		code = slap_str2ad( s_at[ i ].name,
				s_at[ i ].ad, &err );
		if ( code != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"unable to find AttributeDescription "
				"\"%s\": %d (%s)\n",
				s_at[ i ].name, code, err );
			code = LDAP_UNDEFINED_TYPE;
			goto done_at;
		}

done_at:;
		if ( code ) {
			ldap_attributetype_free( at );
			return code;
		}

		ldap_memfree( at );
	}

	for ( i = 0; s_oc[ i ].name != NULL; i++ ) {
		LDAPObjectClass *oc;

		oc = ldap_str2objectclass( s_oc[ i ].desc,
				&code, &err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"ObjectClass load failed: %s %s\n",
				ldap_scherr2str( code ), err, 0 );
			return LDAP_INVALID_SYNTAX;
		}

		code = oc_add( oc, 0, NULL, &err );
		if ( code != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"ObjectClass load failed: %s %s\n",
				scherr2str( code ), err, 0 );
			code = LDAP_INVALID_SYNTAX;
			goto done_oc;
		}

		*s_oc[ i ].oc = oc_find( s_oc[ i ].name );
		if ( *s_oc[ i ].oc == NULL ) {
			code = LDAP_UNDEFINED_TYPE;
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: "
				"unable to find objectClass \"%s\"\n",
				s_oc[ i ].name, 0, 0 );
			goto done_oc;
		}

done_oc:;
		if ( code != LDAP_SUCCESS ) {
			ldap_objectclass_free( oc );
			return code;
		}

		ldap_memfree( oc );
	}

	return 0;
}

/*
 * call from within bdb_db_init()
 */
int
bdb_monitor_init( BackendDB *be )
{
	return 0;
}

/*
 * call from within bdb_db_open()
 */
int
bdb_monitor_open( BackendDB *be )
{
	struct bdb_info		*bdb = (struct bdb_info *) be->be_private;
	Attribute		*a, *next;
	monitor_callback_t	*cb;
	struct berval		base = BER_BVC( "cn=databases,cn=monitor" );
	struct berval		suffix, filter;
	char			*ptr;
	int			rc = 0;

	/* monitor_back_register_entry_attrs() with a NULL ndn,
	 * base="cn=Databases,cn=Monitor", scope=LDAP_SCOPE_ONE 
	 * and filter="(namingContexts:distinguishedNameMatch:=<suffix>)" */

	suffix.bv_len = ldap_bv2escaped_filter_value_len( &be->be_nsuffix[ 0 ] );
	if ( suffix.bv_len == be->be_nsuffix[ 0 ].bv_len ) {
		suffix = be->be_nsuffix[ 0 ];

	} else {
		ldap_bv2escaped_filter_value( &be->be_nsuffix[ 0 ], &suffix );
	}
	
	filter.bv_len = STRLENOF( "(namingContexts:distinguishedNameMatch:=)" ) + suffix.bv_len;
	ptr = filter.bv_val = ch_malloc( filter.bv_len + 1 );
	ptr = lutil_strcopy( ptr, "(namingContexts:distinguishedNameMatch:=" );
	ptr = lutil_strncopy( ptr, suffix.bv_val, suffix.bv_len );
	ptr[ 0 ] = ')';
	ptr++;
	ptr[ 0 ] = '\0';
	assert( filter.bv_len == ptr - filter.bv_val );
	
	if ( suffix.bv_val != be->be_nsuffix[ 0 ].bv_val ) {
		ch_free( suffix.bv_val );
	}

	/* alloc as many as required (plus 1 for objectClass) */
	a = attrs_alloc( 1 + 1 );
	if ( a == NULL ) {
		rc = 1;
		goto cleanup;
	}

	a->a_desc = slap_schema.si_ad_objectClass;
	a->a_vals = NULL;
	value_add_one( &a->a_vals, &oc_olmBDBDatabase->soc_cname );
	a->a_nvals = a->a_vals;
	next = a->a_next;

	/* NOTE: dummy code that increments a olmBDBCounter
	 * any time it's called; replace with something useful */
	{
		struct berval	bv = BER_BVC( "0" );

		next->a_desc = ad_olmBDBCounter;
		next->a_vals = NULL;
		value_add_one( &next->a_vals, &bv );
		next->a_nvals = next->a_vals;
		next = a->a_next;
	}

	cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
	cb->mc_update = bdb_monitor_update;
	cb->mc_modify = bdb_monitor_modify;
	cb->mc_free = bdb_monitor_free;
	cb->mc_private = (void *)bdb;

	rc = monitor_back_register_entry_attrs( NULL,
		a, cb, &base, LDAP_SCOPE_ONELEVEL, &filter );

cleanup:;
	if ( rc != 0 ) {
		if ( cb != NULL ) {
			ch_free( cb );
		}

		if ( a != NULL ) {
			attrs_free( a );
		}
	}
	
	return rc;
}

/*
 * call from within bdb_db_close()
 */
int
bdb_monitor_close( BackendDB *be )
{
	return 0;
}

/*
 * call from within bdb_db_destroy()
 */
int
bdb_monitor_destroy( BackendDB *be )
{
	return 0;
}


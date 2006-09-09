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

static AttributeDescription	*ad_olmBDBEntryCache,
	*ad_olmBDBEntryInfo, *ad_olmBDBIDLCache,
	*ad_olmDbDirectory;

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

static struct {
	char			*name;
	char			*oid;
}		s_oid[] = {
	{ "olmBDBAttributes",			"olmDatabaseAttributes:1" },
	{ "olmBDBObjectClasses",		"olmDatabaseObjectClasses:1" },

	{ NULL }
};

static struct {
	char			*name;
	char			*desc;
	AttributeDescription	**ad;
}		s_at[] = {
	{ "olmBDBEntryCache", "( olmBDBAttributes:1 "
		"NAME ( 'olmBDBEntryCache' ) "
		"DESC 'Number of items in Entry Cache' "
		"SUP monitorCounter "
		"NO-USER-MODIFICATION "
		"USAGE directoryOperation )",
		&ad_olmBDBEntryCache },

	{ "olmBDBEntryInfo", "( olmBDBAttributes:2 "
		"NAME ( 'olmBDBEntryInfo' ) "
		"DESC 'Number of items in EntryInfo Cache' "
		"SUP monitorCounter "
		"NO-USER-MODIFICATION "
		"USAGE directoryOperation )",
		&ad_olmBDBEntryInfo },

	{ "olmBDBIDLCache", "( olmBDBAttributes:3 "
		"NAME ( 'olmBDBIDLCache' ) "
		"DESC 'Number of items in IDL Cache' "
		"SUP monitorCounter "
		"NO-USER-MODIFICATION "
		"USAGE directoryOperation )",
		&ad_olmBDBIDLCache },

	{ "olmDbDirectory", "( olmBDBAttributes:4 "
		"NAME ( 'olmDbDirectory' ) "
		"DESC 'Path name of the directory "
			"where the database environment resides' "
		"SUP monitoredInfo "
		"NO-USER-MODIFICATION "
		"USAGE directoryOperation )",
		&ad_olmDbDirectory },

	{ NULL }
};

static struct {
	char		*name;
	char		*desc;
	ObjectClass	**oc;
}		s_oc[] = {
	/* augments an existing object, so it must be AUXILIARY
	 * FIXME: derive from some ABSTRACT "monitoredEntity"? */
	{ "olmBDBDatabase", "( olmBDBObjectClasses:1 "
		"NAME ( 'olmBDBDatabase' ) "
		"SUP top AUXILIARY "
		"MAY ( "
			"olmBDBEntryCache "
			"$ olmBDBEntryInfo "
			"$ olmBDBIDLCache "
			"$ olmDbDirectory "
			") )",
		&oc_olmBDBDatabase },

	{ NULL }
};

static int
bdb_monitor_update(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	void		*priv )
{
	struct bdb_info		*bdb = (struct bdb_info *) priv;
	Attribute		*a;

	char			buf[ BUFSIZ ];
	struct berval		bv;

	assert( ad_olmBDBEntryCache != NULL );

	a = attr_find( e->e_attrs, ad_olmBDBEntryCache );
	assert( a != NULL );
	bv.bv_val = buf;
	bv.bv_len = snprintf( buf, sizeof( buf ), "%d", bdb->bi_cache.c_cursize );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmBDBEntryInfo );
	assert( a != NULL );
	bv.bv_len = snprintf( buf, sizeof( buf ), "%d", bdb->bi_cache.c_eiused );
	ber_bvreplace( &a->a_vals[ 0 ], &bv );

	a = attr_find( e->e_attrs, ad_olmBDBIDLCache );
	assert( a != NULL );
	bv.bv_len = snprintf( buf, sizeof( buf ), "%d", bdb->bi_idl_cache_size );
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

	struct berval	values[ 2 ];
	Modification	mod = { 0 };

	const char	*text;
	char		textbuf[ SLAP_TEXT_BUFLEN ];

	int		i, rc;

	/* Remove objectClass */
	mod.sm_op = LDAP_MOD_DELETE;
	mod.sm_desc = slap_schema.si_ad_objectClass;
	mod.sm_values = values;
	values[ 0 ] = oc_olmBDBDatabase->soc_cname;
	BER_BVZERO( &values[ 1 ] );

	rc = modify_delete_values( e, &mod, 1, &text,
		textbuf, sizeof( textbuf ) );
	/* don't care too much about return code... */

	/* remove attrs */
	for ( i = 0; s_at[ i ].name != NULL; i++ ) {
		mod.sm_desc = *s_at[ i ].ad;
		mod.sm_values = NULL;
		rc = modify_delete_values( e, &mod, 1, &text,
			textbuf, sizeof( textbuf ) );
		/* don't care too much about return code... */
	}
	
	return SLAP_CB_CONTINUE;
}

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

	for ( i = 0; s_oid[ i ].name; i++ ) {
		char	*argv[ 3 ];
	
		argv[ 0 ] = "back-bdb/back-hdb monitor";
		argv[ 1 ] = s_oid[ i ].name;
		argv[ 2 ] = s_oid[ i ].oid;

		if ( parse_oidm( argv[ 0 ], i, 3, argv, 0, NULL ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_monitor_initialize: unable to add "
				"objectIdentifier \"%s=%s\"\n",
				s_oid[ i ].name, s_oid[ i ].oid, 0 );
			return 1;
		}
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
	SLAP_DBFLAGS( be ) |= SLAP_DBFLAG_MONITORING;

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
	struct berval		suffix, *filter, *base;
	char			*ptr;
	int			rc = 0;

	if ( !SLAP_DBMONITORING( be ) ) {
		return 0;
	}

	/* don't bother if monitor is not configured */
	if ( !monitor_back_is_configured() ) {
		static int warning = 0;

		if ( warning++ == 0 ) {
			Debug( LDAP_DEBUG_ANY, "bdb_monitor_open: "
				"monitoring disabled; "
				"configure monitor database to enable\n",
				0, 0, 0 );
		}

		return 0;
	}

	bdb->bi_monitor.bdm_scope = LDAP_SCOPE_SUBORDINATE;
	base = &bdb->bi_monitor.bdm_nbase;
	BER_BVSTR( base, "cn=databases,cn=monitor" );
	filter = &bdb->bi_monitor.bdm_filter;
	BER_BVZERO( filter );

	suffix.bv_len = ldap_bv2escaped_filter_value_len( &be->be_nsuffix[ 0 ] );
	if ( suffix.bv_len == be->be_nsuffix[ 0 ].bv_len ) {
		suffix = be->be_nsuffix[ 0 ];

	} else {
		ldap_bv2escaped_filter_value( &be->be_nsuffix[ 0 ], &suffix );
	}
	
	filter->bv_len = STRLENOF( "(&(monitoredInfo=" )
		+ strlen( be->bd_info->bi_type )
		+ STRLENOF( ")(namingContexts:distinguishedNameMatch:=" )
		+ suffix.bv_len + STRLENOF( "))" );
	ptr = filter->bv_val = ch_malloc( filter->bv_len + 1 );
	ptr = lutil_strcopy( ptr, "(&(monitoredInfo=" );
	ptr = lutil_strcopy( ptr, be->bd_info->bi_type );
	ptr = lutil_strcopy( ptr, ")(namingContexts:distinguishedNameMatch:=" );
	ptr = lutil_strncopy( ptr, suffix.bv_val, suffix.bv_len );
	ptr = lutil_strcopy( ptr, "))" );
	ptr[ 0 ] = '\0';
	assert( filter->bv_len == ptr - filter->bv_val );
	
	if ( suffix.bv_val != be->be_nsuffix[ 0 ].bv_val ) {
		ch_free( suffix.bv_val );
	}

	/* alloc as many as required (plus 1 for objectClass) */
	a = attrs_alloc( 1 + 4 );
	if ( a == NULL ) {
		rc = 1;
		goto cleanup;
	}

	a->a_desc = slap_schema.si_ad_objectClass;
	value_add_one( &a->a_vals, &oc_olmBDBDatabase->soc_cname );
	a->a_nvals = a->a_vals;
	next = a->a_next;

	{
		struct berval	bv = BER_BVC( "0" );

		next->a_desc = ad_olmBDBEntryCache;
		value_add_one( &next->a_vals, &bv );
		next->a_nvals = next->a_vals;
		next = next->a_next;

		next->a_desc = ad_olmBDBEntryInfo;
		value_add_one( &next->a_vals, &bv );
		next->a_nvals = next->a_vals;
		next = next->a_next;

		next->a_desc = ad_olmBDBIDLCache;
		value_add_one( &next->a_vals, &bv );
		next->a_nvals = next->a_vals;
		next = next->a_next;
	}

	{
		struct berval	bv, nbv;
		ber_len_t	pathlen = 0, len = 0;
		char		path[ PATH_MAX ] = { '\0' };
		char		*fname = bdb->bi_dbenv_home,
				*ptr;

		len = strlen( fname );
		if ( fname[ 0 ] != '/' ) {
			/* get full path name */
			getcwd( path, sizeof( path ) );
			pathlen = strlen( path );

			if ( fname[ 0 ] == '.' && fname[ 1 ] == '/' ) {
				fname += 2;
				len -= 2;
			}
		}

		bv.bv_len = pathlen + STRLENOF( "/" ) + len;
		ptr = bv.bv_val = ch_malloc( bv.bv_len + STRLENOF( "/" ) + 1 );
		if ( pathlen ) {
			ptr = lutil_strncopy( ptr, path, pathlen );
			ptr[ 0 ] = '/';
			ptr++;
		}
		ptr = lutil_strncopy( ptr, fname, len );
		if ( ptr[ -1 ] != '/' ) {
			ptr[ 0 ] = '/';
			ptr++;
		}
		ptr[ 0 ] = '\0';
		
		attr_normalize_one( ad_olmDbDirectory, &bv, &nbv, NULL );

		next->a_desc = ad_olmDbDirectory;
		next->a_vals = ch_calloc( sizeof( struct berval ), 2 );
		next->a_vals[ 0 ] = bv;

		if ( BER_BVISNULL( &nbv ) ) {
			next->a_nvals = next->a_vals;

		} else {
			next->a_nvals = ch_calloc( sizeof( struct berval ), 2 );
			next->a_nvals[ 0 ] = nbv;
		}

		next = next->a_next;
	}

	cb = ch_calloc( sizeof( monitor_callback_t ), 1 );
	cb->mc_update = bdb_monitor_update;
	cb->mc_modify = bdb_monitor_modify;
	cb->mc_free = bdb_monitor_free;
	cb->mc_private = (void *)bdb;

	rc = monitor_back_register_entry_attrs( NULL, a, cb,
		base, LDAP_SCOPE_SUBORDINATE, filter );

cleanup:;
	if ( rc != 0 ) {
		if ( cb != NULL ) {
			ch_free( cb );
			cb = NULL;
		}

		if ( a != NULL ) {
			attrs_free( a );
			a = NULL;
		}

		if ( !BER_BVISNULL( filter ) ) {
			ch_free( filter->bv_val );
			BER_BVZERO( filter );
		}
	}

	/* store for cleanup */
	bdb->bi_monitor.bdm_cb = (void *)cb;

	/* we don't need to keep track of the attributes, because
	 * bdb_monitor_free() takes care of everything */
	if ( a != NULL ) {
		attrs_free( a );
	}

	return rc;
}

/*
 * call from within bdb_db_close()
 */
int
bdb_monitor_close( BackendDB *be )
{
	struct bdb_info		*bdb = (struct bdb_info *) be->be_private;

	if ( !BER_BVISNULL( &bdb->bi_monitor.bdm_filter ) ) {
		monitor_back_unregister_entry_callback( NULL,
			(monitor_callback_t *)bdb->bi_monitor.bdm_cb,
			&bdb->bi_monitor.bdm_nbase,
			bdb->bi_monitor.bdm_scope,
			&bdb->bi_monitor.bdm_filter );

		if ( !BER_BVISNULL( &bdb->bi_monitor.bdm_filter ) ) {
			ch_free( bdb->bi_monitor.bdm_filter.bv_val );
		}

		memset( &bdb->bi_monitor, 0, sizeof( bdb->bi_monitor ) );
	}

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


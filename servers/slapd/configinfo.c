/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#if defined( SLAPD_CONFIG_DN )

/*
 * no mutex protection in here - take our chances!
 */

void
config_info(
	Connection *conn,
	Operation *op,
	char **attrs,
	int attrsonly )
{
	Entry		*e;
	char		buf[BUFSIZ];
	struct berval	val;
	struct berval	*vals[2];
	int		i, j;

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	e->e_dn = ch_strdup( SLAPD_CONFIG_DN );
	e->e_ndn = ch_strdup( SLAPD_CONFIG_DN );
	(void) dn_normalize( e->e_ndn );
	e->e_private = NULL;

	{
		char *rdn = ch_strdup( SLAPD_CONFIG_DN );
		val.bv_val = strchr( rdn, '=' );

		if( val.bv_val != NULL ) {
			*val.bv_val = '\0';
			val.bv_len = strlen( ++val.bv_val );

			attr_merge( e, rdn, vals );
		}

		free( rdn );
	}

	for ( i = 0; i < nbackends; i++ ) {
		strcpy( buf, backends[i].be_type );
		for ( j = 0; backends[i].be_suffix[j] != NULL; j++ ) {
			strcat( buf, " : " );
			strcat( buf, backends[i].be_suffix[j] );
		}
		val.bv_val = buf;
		val.bv_len = strlen( buf );
		attr_merge( e, "database", vals );
	}

	val.bv_val = "top";
	val.bv_len = sizeof("top")-1;
	attr_merge( e, "objectClass", vals );

	val.bv_val = "LDAPsubentry";
	val.bv_len = sizeof("LDAPsubentry")-1;
	attr_merge( e, "objectClass", vals );

	val.bv_val = "extensibleObject";
	val.bv_len = sizeof("extensibleObject")-1;
	attr_merge( e, "objectClass", vals );

	send_search_entry( &backends[0], conn, op, e,
		attrs, attrsonly, NULL );
	send_search_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL, 1 );

	entry_free( e );
}

#endif /* slapd_config_dn */

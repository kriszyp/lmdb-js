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

#include "ldap_defaults.h"
#include "slap.h"

#if defined( SLAPD_CONFIG_DN )

/*
 * no mutex protection in here - take our chances!
 */

void
config_info( Connection *conn, Operation *op )
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
	e->e_ndn = dn_normalize_case( ch_strdup( SLAPD_CONFIG_DN ));
	e->e_private = NULL;

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

	send_search_entry( &backends[0], conn, op, e,
		NULL, 0, 1, NULL );
	send_search_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL, 1 );

	entry_free( e );
}

#endif /* slapd_config_dn */

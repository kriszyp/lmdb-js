/* add.c - DNS SRV backend request handler */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-dnssrv.h"

int
dnssrv_back_request(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char *dn,
    const char *ndn )
{
	int i;
	char *domain = NULL;
	char *hostlist = NULL;
	char **hosts = NULL;
	struct berval **urls = NULL;

	if( ldap_dn2domain( dn, &domain ) ) {
		send_ldap_result( conn, op, LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		goto done;
	}
	
	if( ldap_domain2hostlist( dn, &domain ) ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			NULL, NULL, NULL, NULL );
		goto done;
	}

	hosts = str2charray( hostlist, " " );

	if( hosts == NULL ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, NULL, NULL, NULL );
		goto done;
	}

	for( i=0; hosts[i] != NULL; i++) {
		struct berval *url = ch_malloc( sizeof( struct berval ) );

		url->bv_len = sizeof("ldap://") + strlen(hosts[i]);
		url->bv_val = ch_malloc( url->bv_len );

		strcpy( url->bv_val, "ldap://" );
		strcpy( &url->bv_val[sizeof("ldap://")-1], hosts[i] );

		if( ber_bvecadd( &urls, url ) < 0) {
			ber_bvfree( url );
			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, NULL, NULL, NULL );
			goto done;
		}
	}

	send_ldap_result( conn, op, LDAP_REFERRAL,
		NULL, NULL, urls, NULL );

done:
	if( domain != NULL ) ch_free( domain );
	if( hostlist != NULL ) ch_free( hostlist );
	if( hosts != NULL ) charray_free( hosts );
	if( urls != NULL ) ber_bvecfree( urls );
	return 0;
}

/* referral.c - DNS SRV backend referral handler */
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
#include "external.h"

int
dnssrv_back_referrals(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char *dn,
    const char *ndn,
	const char **text )
{
	int i;
	int rc = LDAP_OTHER;
	char *domain = NULL;
	char *hostlist = NULL;
	char **hosts = NULL;
	struct berval **urls = NULL;

	if( ndn == NULL || *ndn == '\0' ) {
		*text = "operation upon null (empty) DN disallowed";
		return LDAP_UNWILLING_TO_PERFORM;
	}

	if( get_manageDSAit( op ) ) {
		if( op->o_tag == LDAP_REQ_SEARCH ) {
			return LDAP_SUCCESS;
		}

		*text = "DNS SRV problem processing manageDSAit control";
		return LDAP_OTHER;
	} 

	if( ldap_dn2domain( dn, &domain ) ) {
		send_ldap_result( conn, op, LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		return LDAP_REFERRAL;
	}

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: dn=\"%s\" -> domain=\"%s\"\n",
		dn == NULL ? "" : dn,
		domain == NULL ? "" : domain,
		0 );

	if( rc = ldap_domain2hostlist( domain, &hostlist ) ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: domain2hostlist returned %d\n",
			rc, 0, 0 );
		*text = "no DNS SRV RR available for DN";
		rc = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

	hosts = str2charray( hostlist, " " );

	if( hosts == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: str2charrary error\n", 0, 0, 0 );
		*text = "problem processing DNS SRV records for DN";
		goto done;
	}

	for( i=0; hosts[i] != NULL; i++) {
		struct berval *url = ch_malloc( sizeof( struct berval ) ); 

		url->bv_len = sizeof("ldap://")-1 + strlen(hosts[i]);
		url->bv_val = ch_malloc( url->bv_len + 1 );

		strcpy( url->bv_val, "ldap://" );
		strcpy( &url->bv_val[sizeof("ldap://")-1], hosts[i] );

		if( ber_bvecadd( &urls, url ) < 0 ) {
			ber_bvfree( url );
			*text = "problem processing DNS SRV records for DN";
			goto done;
		}
	}

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%d DNSSRV p=%d dn=\"%s\" url=\"%s\"\n",
	    op->o_connid, op->o_opid, op->o_protocol, dn, urls[0]->bv_val );

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: dn=\"%s\" -> url=\"%s\"\n",
		dn == NULL ? "" : dn,
		urls[0]->bv_val, 0 );

	send_ldap_result( conn, op, rc = LDAP_REFERRAL,
		NULL, "DNS SRV generated referrals", urls, NULL );

done:
	if( domain != NULL ) ch_free( domain );
	if( hostlist != NULL ) ch_free( hostlist );
	if( hosts != NULL ) charray_free( hosts );
	ber_bvecfree( urls );
	return rc;
}

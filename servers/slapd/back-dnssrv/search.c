/* search.c - DNS SRV backend search function */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "external.h"

int
dnssrv_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval	*dn,
    struct berval	*ndn,
    int		scope,
    int		deref,
    int		size,
    int		time,
    Filter	*filter,
    struct berval	*filterstr,
    AttributeName	*attrs,
    int		attrsonly )
{
	int i;
	int rc;
	char *domain = NULL;
	char *hostlist = NULL;
	char **hosts = NULL;
	char *refdn;
	struct berval nrefdn = { 0, NULL };
	BerVarray urls = NULL;

	assert( get_manageDSAit( op ) );

	if( ldap_dn2domain( dn->bv_val, &domain ) ) {
		send_ldap_result( conn, op, LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		goto done;
	}

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: dn=\"%s\" -> domain=\"%s\"\n",
		dn->bv_len ? dn->bv_val : "",
		domain == NULL ? "" : domain,
		0 );

	if( ( rc = ldap_domain2hostlist( domain, &hostlist ) ) ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: domain2hostlist returned %d\n",
			rc, 0, 0 );
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			NULL, "no DNS SRV RR available for DN", NULL, NULL );
		goto done;
	}

	hosts = ldap_str2charray( hostlist, " " );

	if( hosts == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: str2charrary error\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "problem processing DNS SRV records for DN", NULL, NULL );
		goto done;
	}

	for( i=0; hosts[i] != NULL; i++) {
		struct berval url;

		url.bv_len = sizeof("ldap://")-1 + strlen(hosts[i]);
		url.bv_val = ch_malloc( url.bv_len + 1 );

		strcpy( url.bv_val, "ldap://" );
		strcpy( &url.bv_val[sizeof("ldap://")-1], hosts[i] );

		if( ber_bvarray_add( &urls, &url ) < 0 ) {
			free( url.bv_val );
			send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "problem processing DNS SRV records for DN",
			NULL, NULL );
			goto done;
		}
	}

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%lu op=%lu DNSSRV p=%d dn=\"%s\" url=\"%s\"\n",
	    op->o_connid, op->o_opid, op->o_protocol,
		dn->bv_len ? dn->bv_val : "", urls[0].bv_val );

	Debug( LDAP_DEBUG_TRACE,
		"DNSSRV: ManageDSAit scope=%d dn=\"%s\" -> url=\"%s\"\n",
		scope,
		dn->bv_len ? dn->bv_val : "",
		urls[0].bv_val );

	rc = ldap_domain2dn(domain, &refdn);

	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DNS SRV problem processing manageDSAit control",
			NULL, NULL );
		goto done;

	} else {
		struct berval bv;
		bv.bv_val = refdn;
		bv.bv_len = strlen( refdn );

		rc = dnNormalize2( NULL, &bv, &nrefdn );
		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "DNS SRV problem processing manageDSAit control",
				NULL, NULL );
			goto done;
		}
	}

	if( !dn_match( &nrefdn, ndn ) ) {
		/* requested dn is subordinate */

		Debug( LDAP_DEBUG_TRACE,
			"DNSSRV: dn=\"%s\" subordindate to refdn=\"%s\"\n",
			dn->bv_len ? dn->bv_val : "",
			refdn == NULL ? "" : refdn,
			NULL );

		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			refdn, NULL,
			NULL, NULL );

	} else if ( scope == LDAP_SCOPE_ONELEVEL ) {
		send_ldap_result( conn, op, LDAP_SUCCESS,
			NULL, NULL, NULL, NULL );

	} else {
		struct berval	vals[2];
		Entry *e = ch_calloc( 1, sizeof(Entry) );
		AttributeDescription *ad_objectClass
			= slap_schema.si_ad_objectClass;
		AttributeDescription *ad_ref = slap_schema.si_ad_ref;
		e->e_dn = strdup( dn->bv_val );
		e->e_name.bv_len = dn->bv_len;
		e->e_ndn = strdup( ndn->bv_val );
		e->e_nname.bv_len = ndn->bv_len;

		e->e_attrs = NULL;
		e->e_private = NULL;

		vals[1].bv_val = NULL;

		vals[0].bv_val = "top";
		vals[0].bv_len = sizeof("top")-1;
		attr_merge( e, ad_objectClass, vals );

		vals[0].bv_val = "referral";
		vals[0].bv_len = sizeof("referral")-1;
		attr_merge( e, ad_objectClass, vals );

		vals[0].bv_val = "extensibleObject";
		vals[0].bv_len = sizeof("extensibleObject")-1;
		attr_merge( e, ad_objectClass, vals );

		{
			AttributeDescription *ad = NULL;
			const char *text;

			rc = slap_str2ad( "dc", &ad, &text );

			if( rc == LDAP_SUCCESS ) {
				char *p;
				vals[0].bv_val = ch_strdup( domain );

				p = strchr( vals[0].bv_val, '.' );
					
				if( p == vals[0].bv_val ) {
					vals[0].bv_val[1] = '\0';
				} else if ( p != NULL ) {
					*p = '\0';
				}

				vals[0].bv_len = strlen(vals[0].bv_val);
				attr_merge( e, ad, vals );
			}
		}

		{
			AttributeDescription *ad = NULL;
			const char *text;

			rc = slap_str2ad( "associatedDomain", &ad, &text );

			if( rc == LDAP_SUCCESS ) {
				vals[0].bv_val = domain;
				vals[0].bv_len = strlen(domain);
				attr_merge( e, ad, vals );
			}
		}

		attr_merge( e, ad_ref, urls );

		rc = test_filter( be, conn, op, e, filter ); 

		if( rc == LDAP_COMPARE_TRUE ) {
			send_search_entry( be, conn, op,
				e, attrs, attrsonly, NULL );
		}

		entry_free( e );
			
		send_ldap_result( conn, op, LDAP_SUCCESS,
			NULL, NULL, NULL, NULL );
	}

	if ( refdn ) free( refdn );
	if ( nrefdn.bv_val ) free( nrefdn.bv_val );

done:
	if( domain != NULL ) ch_free( domain );
	if( hostlist != NULL ) ch_free( hostlist );
	if( hosts != NULL ) ldap_charray_free( hosts );
	if( urls != NULL ) ber_bvarray_free( urls );
	return 0;
}

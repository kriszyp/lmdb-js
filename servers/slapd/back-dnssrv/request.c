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
    const char *ndn,
	int scope, Filter *filter,
	char **attrs, int attrsonly )
{
	int i;
	int rc;
	char *domain = NULL;
	char *hostlist = NULL;
	char **hosts = NULL;
	struct berval **urls = NULL;
	int		manageDSAit = get_manageDSAit( op );

	if( ndn == NULL || *ndn == '\0' ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation upon null (empty) DN disallowed",
			NULL, NULL );
		goto done;
	}

	if( ldap_dn2domain( dn, &domain ) ) {
		send_ldap_result( conn, op, LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		goto done;
	}

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: dn=\"%s\" -> domain=\"%s\"\n",
		dn == NULL ? "" : dn,
		domain == NULL ? "" : domain,
		0 );

	if( rc = ldap_domain2hostlist( domain, &hostlist ) ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: domain2hostlist returned %d\n",
			rc, 0, 0 );
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			NULL, "no DNS SRV RR available for DN", NULL, NULL );
		goto done;
	}

	hosts = str2charray( hostlist, " " );

	if( hosts == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: str2charrary error\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "problem processing DNS SRV records for DN", NULL, NULL );
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
			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "problem processing DNS SRV records for DN",
				NULL, NULL );
			goto done;
		}
	}

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%d DNSSRV p=%d dn=\"%s\" url=\"%s\"\n",
	    op->o_connid, op->o_opid, op->o_protocol, dn, urls[0]->bv_val );

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: %sdn=\"%s\" -> url=\"%s\"\n",
		manageDSAit ? "ManageDSAit " : "",
		dn == NULL ? "" : dn,
		urls[0]->bv_val );

	if( manageDSAit ) {
		char *refdn, *nrefdn;
		rc = ldap_domain2dn(domain, &refdn);

		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "DNS SRV problem processing manageDSAit control",
				NULL, NULL );
			goto done;
		}

		nrefdn = ch_strdup( refdn );
		dn_normalize(nrefdn);

		if( strcmp( nrefdn, ndn ) != 0 ) {
			/* requested dn is subordinate */

			Debug( LDAP_DEBUG_TRACE,
					"DNSSRV: dn=\"%s\" subordindate to refdn=\"%s\"\n",
					dn == NULL ? "" : dn,
					refdn == NULL ? "" : refdn,
					NULL );

			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
				refdn, NULL,
				NULL, NULL );

		} else if( op->o_tag != LDAP_REQ_SEARCH ) {
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
				dn, "DNS SRV ManageDSAIT control disallowed",
				NULL, NULL );

		} else if ( scope != LDAP_SCOPE_ONELEVEL ) {
			struct berval	val;
			struct berval	*vals[2];
			Entry *e = ch_calloc( 1, sizeof(Entry) );
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			AttributeDescription *ad_objectClass
				= slap_schema.si_ad_objectClass;
			AttributeDescription *ad_ref = slap_schema.si_ad_ref;
#else
			const char ad_objectClass = "objectClass";
			const char ad_ref = "ref";
#endif
			e->e_dn = strdup( dn );
			e->e_ndn = strdup( ndn );

			e->e_attrs = NULL;
			e->e_private = NULL;

			vals[0] = &val;
			vals[1] = NULL;

			val.bv_val = "top";
			val.bv_len = sizeof("top")-1;
			attr_merge( e, ad_objectClass, vals );

			val.bv_val = "referral";
			val.bv_len = sizeof("referral")-1;
			attr_merge( e, ad_objectClass, vals );

			val.bv_val = "extensibleObject";
			val.bv_len = sizeof("extensibleObject")-1;
			attr_merge( e, ad_objectClass, vals );

			{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				AttributeDescription *ad = NULL;
				const char *text;

				rc = slap_str2ad( "dc", &ad, &text );
#else
				rc = LDAP_SUCCESS;
				const char *ad = "dc";
#endif

				if( rc == LDAP_SUCCESS ) {
					char *p;
					val.bv_val = ch_strdup( domain );

					p = strchr( val.bv_val, '.' );
					
					if( p == val.bv_val ) {
						val.bv_val[1] = '\0';
					} else if ( p != NULL ) {
						*p = '\0';
					}

					val.bv_len = strlen(val.bv_val);
					attr_merge( e, ad, vals );

					ad_free( ad, 1 );
				}
			}

			{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				AttributeDescription *ad = NULL;
				const char *text;

				rc = slap_str2ad( "associatedDomain", &ad, &text );
#else
				rc = LDAP_SUCCESS;
				const char *ad = "associatedDomain";
#endif

				if( rc == LDAP_SUCCESS ) {
					val.bv_val = domain;
					val.bv_len = strlen(domain);
					attr_merge( e, ad, vals );

					ad_free( ad, 1 );
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

		} else {
			send_ldap_result( conn, op, LDAP_SUCCESS,
				NULL, NULL, NULL, NULL );
		}

		free( refdn );
		free( nrefdn );

	} else {
		send_ldap_result( conn, op, LDAP_REFERRAL,
			NULL, "DNS SRV generated referrals", urls, NULL );
	}

done:
	if( domain != NULL ) ch_free( domain );
	if( hostlist != NULL ) ch_free( hostlist );
	if( hosts != NULL ) charray_free( hosts );
	if( urls != NULL ) ber_bvecfree( urls );
	return 0;
}

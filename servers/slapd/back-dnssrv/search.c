/* search.c - DNS SRV backend search function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
 * Portions Copyright 2000-2003 Kurt D. Zeilenga.
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
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by Kurt D. Zeilenga for inclusion
 * in OpenLDAP Software.
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
    Operation	*op,
    SlapReply	*rs )
{
	int i;
	int rc;
	char *domain = NULL;
	char *hostlist = NULL;
	char **hosts = NULL;
	char *refdn;
	struct berval nrefdn = BER_BVNULL;
	BerVarray urls = NULL;
	int manageDSAit;

	rs->sr_ref = NULL;

	manageDSAit = get_manageDSAit( op );
	/*
	 * FIXME: we may return a referral if manageDSAit is not set
	 */
	if ( ! manageDSAit ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"manageDSAit must be set" );
		goto done;
	}

	if( ldap_dn2domain( op->o_req_dn.bv_val, &domain ) || domain == NULL ) {
		rs->sr_err = LDAP_REFERRAL;
		rs->sr_ref = default_referral;
		send_ldap_result( op, rs );
		rs->sr_ref = NULL;
		goto done;
	}

	Debug( LDAP_DEBUG_TRACE, "DNSSRV: dn=\"%s\" -> domain=\"%s\"\n",
		op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "", domain, 0 );

	if( ( rc = ldap_domain2hostlist( domain, &hostlist ) ) ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: domain2hostlist returned %d\n",
			rc, 0, 0 );
		send_ldap_error( op, rs, LDAP_NO_SUCH_OBJECT,
			"no DNS SRV RR available for DN" );
		goto done;
	}

	hosts = ldap_str2charray( hostlist, " " );

	if( hosts == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: str2charrary error\n", 0, 0, 0 );
		send_ldap_error( op, rs, LDAP_OTHER,
			"problem processing DNS SRV records for DN" );
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
			send_ldap_error( op, rs, LDAP_OTHER,
			"problem processing DNS SRV records for DN" );
			goto done;
		}
	}

	Statslog( LDAP_DEBUG_STATS,
	    "%s DNSSRV p=%d dn=\"%s\" url=\"%s\"\n",
	    op->o_log_prefix, op->o_protocol,
		op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "", urls[0].bv_val, 0 );

	Debug( LDAP_DEBUG_TRACE,
		"DNSSRV: ManageDSAit scope=%d dn=\"%s\" -> url=\"%s\"\n",
		op->oq_search.rs_scope,
		op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "",
		urls[0].bv_val );

	rc = ldap_domain2dn(domain, &refdn);

	if( rc != LDAP_SUCCESS ) {
		send_ldap_error( op, rs, LDAP_OTHER,
			"DNS SRV problem processing manageDSAit control" );
		goto done;

	} else {
		struct berval bv;
		bv.bv_val = refdn;
		bv.bv_len = strlen( refdn );

		rc = dnNormalize( 0, NULL, NULL, &bv, &nrefdn, op->o_tmpmemctx );
		if( rc != LDAP_SUCCESS ) {
			send_ldap_error( op, rs, LDAP_OTHER,
				"DNS SRV problem processing manageDSAit control" );
			goto done;
		}
	}

	if( !dn_match( &nrefdn, &op->o_req_ndn ) ) {
		/* requested dn is subordinate */

		Debug( LDAP_DEBUG_TRACE,
			"DNSSRV: dn=\"%s\" subordinate to refdn=\"%s\"\n",
			op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "",
			refdn == NULL ? "" : refdn,
			NULL );

		rs->sr_matched = refdn;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		send_ldap_result( op, rs );
		rs->sr_matched = NULL;

	} else if ( op->oq_search.rs_scope == LDAP_SCOPE_ONELEVEL ) {
		send_ldap_error( op, rs, LDAP_SUCCESS, NULL );

	} else {
		struct berval	vals[2];
		Entry *e = ch_calloc( 1, sizeof(Entry) );
		AttributeDescription *ad_objectClass
			= slap_schema.si_ad_objectClass;
		AttributeDescription *ad_ref = slap_schema.si_ad_ref;
		e->e_name.bv_val = strdup( op->o_req_dn.bv_val );
		e->e_name.bv_len = op->o_req_dn.bv_len;
		e->e_nname.bv_val = strdup( op->o_req_ndn.bv_val );
		e->e_nname.bv_len = op->o_req_ndn.bv_len;

		e->e_attrs = NULL;
		e->e_private = NULL;

		vals[1].bv_val = NULL;

		vals[0].bv_val = "top";
		vals[0].bv_len = sizeof("top")-1;
		attr_mergeit( e, ad_objectClass, vals );

		vals[0].bv_val = "referral";
		vals[0].bv_len = sizeof("referral")-1;
		attr_mergeit( e, ad_objectClass, vals );

		vals[0].bv_val = "extensibleObject";
		vals[0].bv_len = sizeof("extensibleObject")-1;
		attr_mergeit( e, ad_objectClass, vals );

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
				attr_mergeit( e, ad, vals );
			}
		}

		{
			AttributeDescription *ad = NULL;
			const char *text;

			rc = slap_str2ad( "associatedDomain", &ad, &text );

			if( rc == LDAP_SUCCESS ) {
				vals[0].bv_val = domain;
				vals[0].bv_len = strlen(domain);
				attr_mergeit( e, ad, vals );
			}
		}

		attr_mergeit( e, ad_ref, urls );

		rc = test_filter( op, e, op->oq_search.rs_filter ); 

		if( rc == LDAP_COMPARE_TRUE ) {
			rs->sr_entry = e;
			rs->sr_attrs = op->oq_search.rs_attrs;
			rs->sr_flags = REP_ENTRY_MODIFIABLE;
			send_search_entry( op, rs );
			rs->sr_entry = NULL;
			rs->sr_attrs = NULL;
		}

		entry_free( e );

		rs->sr_err = LDAP_SUCCESS;
		send_ldap_result( op, rs );
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


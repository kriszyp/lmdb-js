/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
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

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi.h"
static char **anlist2charray( Operation *op, AttributeName *an );
static void initSearchPlugin( Operation *op, char **attrs, int managedsait );
static int doPreSearchPluginFNs( Operation *op );
static int doSearchRewriteFNs( Operation *op );
static void doPostSearchPluginFNs( Operation *op );
#endif /* LDAPI_SLAPI */

int
do_search(
    Operation	*op,	/* info about the op to which we're responding */
    SlapReply	*rs	/* all the response data we'll send */
) {
	struct berval base = { 0, NULL };
	ber_len_t	siz, off, i;
	int			manageDSAit;
	int			be_manageDSAit;
#ifdef LDAP_SLAPI
	char		**attrs = NULL;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_search: conn %d\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );
#endif

	/*
	 * Parse the search request.  It looks like this:
	 *
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree	(2)
	 *		},
	 *		derefAliases	ENUMERATED {
	 *			neverDerefaliases	(0),
	 *			derefInSearching	(1),
	 *			derefFindingBaseObj	(2),
	 *			alwaysDerefAliases	(3)
	 *		},
	 *		sizelimit	INTEGER (0 .. 65535),
	 *		timelimit	INTEGER (0 .. 65535),
	 *		attrsOnly	BOOLEAN,
	 *		filter		Filter,
	 *		attributes	SEQUENCE OF AttributeType
	 *	}
	 */

	/* baseObject, scope, derefAliases, sizelimit, timelimit, attrsOnly */
	if ( ber_scanf( op->o_ber, "{miiiib" /*}*/,
		&base, &op->ors_scope, &op->ors_deref, &op->ors_slimit,
	    &op->ors_tlimit, &op->ors_attrsonly ) == LBER_ERROR )
	{
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto return_results;
	}

	switch( op->ors_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
		break;
	default:
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "invalid scope" );
		goto return_results;
	}

	switch( op->ors_deref ) {
	case LDAP_DEREF_NEVER:
	case LDAP_DEREF_FINDING:
	case LDAP_DEREF_SEARCHING:
	case LDAP_DEREF_ALWAYS:
		break;
	default:
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "invalid deref" );
		goto return_results;
	}

	rs->sr_err = dnPrettyNormal( NULL, &base, &op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_search: conn %d  invalid dn (%s)\n",
			op->o_connid, base.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_search: invalid dn (%s)\n", base.bv_val, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, "SRCH \"%s\" %d %d",
		base.bv_val, op->ors_scope, op->ors_deref );
	LDAP_LOG( OPERATION, ARGS, "    %d %d %d\n",
		op->ors_slimit, op->ors_tlimit, op->ors_attrsonly);
#else
	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d",
		base.bv_val, op->ors_scope, op->ors_deref );
	Debug( LDAP_DEBUG_ARGS, "    %d %d %d\n",
		op->ors_slimit, op->ors_tlimit, op->ors_attrsonly);
#endif

	/* filter - returns a "normalized" version */
	rs->sr_err = get_filter( op, op->o_ber, &op->ors_filter, &rs->sr_text );
	if( rs->sr_err != LDAP_SUCCESS ) {
		if( rs->sr_err == SLAPD_DISCONNECT ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			send_ldap_disconnect( op, rs );
		} else {
			send_ldap_result( op, rs );
		}
		goto return_results;
	}
	filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"do_search: conn %d	filter: %s\n", 
		op->o_connid, op->ors_filterstr.bv_len ? op->ors_filterstr.bv_val : "empty", 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "    filter: %s\n",
		op->ors_filterstr.bv_len ? op->ors_filterstr.bv_val : "empty", 0, 0 );
#endif

	/* attributes */
	siz = sizeof(AttributeName);
	off = 0;
	if ( ber_scanf( op->o_ber, "{M}}", &op->ors_attrs, &siz, off ) == LBER_ERROR ) {
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding attrs error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto return_results;
	}
	for ( i=0; i<siz; i++ ) {
		const char *dummy;	/* ignore msgs from bv2ad */
		op->ors_attrs[i].an_desc = NULL;
		op->ors_attrs[i].an_oc = NULL;
		slap_bv2ad(&op->ors_attrs[i].an_name, &op->ors_attrs[i].an_desc, &dummy);
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_search: conn %d  get_ctrls failed (%d)\n",
			op->o_connid, rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_search: get_ctrls failed\n", 0, 0, 0 );
#endif

		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"do_search: conn %d	attrs:", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "    attrs:", 0, 0, 0 );
#endif

	if ( siz != 0 ) {
		for ( i = 0; i<siz; i++ ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ARGS, 
				"do_search: %s", op->ors_attrs[i].an_name.bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_ARGS, " %s", op->ors_attrs[i].an_name.bv_val, 0, 0 );
#endif
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, "\n" , 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );
#endif

	if ( StatslogTest( LDAP_DEBUG_STATS ) ) {
		char abuf[BUFSIZ/2], *ptr = abuf;
		int len = 0, alen;

		sprintf(abuf, "scope=%d deref=%d", op->ors_scope, op->ors_deref);
		Statslog( LDAP_DEBUG_STATS,
		        "conn=%lu op=%lu SRCH base=\"%s\" %s filter=\"%s\"\n",
		        op->o_connid, op->o_opid, op->o_req_dn.bv_val, abuf,
		        op->ors_filterstr.bv_val );

		for ( i = 0; i<siz; i++ ) {
			alen = op->ors_attrs[i].an_name.bv_len;
			if (alen >= sizeof(abuf)) {
				alen = sizeof(abuf)-1;
			}
			if (len && (len + 1 + alen >= sizeof(abuf))) {
				Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu SRCH attr=%s\n",
				    op->o_connid, op->o_opid, abuf, 0, 0 );
				len = 0;
				ptr = abuf;
			}
			if (len) {
				*ptr++ = ' ';
				len++;
			}
			ptr = lutil_strncopy(ptr, op->ors_attrs[i].an_name.bv_val, alen);
			len += alen;
			*ptr = '\0';
		}
		if (len) {
			Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu SRCH attr=%s\n",
	    			op->o_connid, op->o_opid, abuf, 0, 0 );
		}
	}

	manageDSAit = get_manageDSAit( op );

	/* fake while loop to allow breaking out */
	while ( op->ors_scope == LDAP_SCOPE_BASE ) {
		Entry *entry = NULL;

		if ( op->o_req_ndn.bv_len == 0 ) {
#ifdef LDAP_CONNECTIONLESS
			/* Ignore LDAPv2 CLDAP Root DSE queries */
			if (op->o_protocol == LDAP_VERSION2 && op->o_conn->c_is_udp) {
				goto return_results;
			}
#endif
			/* check restrictions */
			if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				goto return_results;
			}

#ifdef LDAP_SLAPI
			if ( op->o_pb ) {
				attrs = anlist2charray( op, op->ors_attrs );
				initSearchPlugin( op, attrs, manageDSAit );
				rs->sr_err = doPreSearchPluginFNs( op );
				if ( rs->sr_err ) break;
				doSearchRewriteFNs( op );
			}
#endif /* LDAP_SLAPI */
			rs->sr_err = root_dse_info( op->o_conn, &entry, &rs->sr_text );

		} else if ( bvmatch( &op->o_req_ndn, &global_schemandn ) ) {
			/* check restrictions */
			if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				goto return_results;
			}

#ifdef LDAP_SLAPI
			if ( op->o_pb ) {
				attrs = anlist2charray( op, op->ors_attrs );
				initSearchPlugin( op, attrs, manageDSAit );
				rs->sr_err = doPreSearchPluginFNs( op );
				if ( rs->sr_err ) break;
				doSearchRewriteFNs( op );
			}
#endif /* LDAP_SLAPI */
			rs->sr_err = schema_info( &entry, &rs->sr_text );
		}

		if( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
#ifdef LDAP_SLAPI
			if ( op->o_pb ) doPostSearchPluginFNs( op );
#endif /* LDAP_SLAPI */
			goto return_results;

		} else if ( entry != NULL ) {
			rs->sr_err = test_filter( op, entry, op->ors_filter );

			if( rs->sr_err == LDAP_COMPARE_TRUE ) {
				rs->sr_entry = entry;
				rs->sr_attrs = op->ors_attrs;
				send_search_entry( op, rs );
				rs->sr_entry = NULL;
			}
			entry_free( entry );

			rs->sr_err = LDAP_SUCCESS;
			send_ldap_result( op, rs );
#ifdef LDAP_SLAPI
			if ( op->o_pb ) doPostSearchPluginFNs( op );
#endif /* LDAP_SLAPI */
			goto return_results;
		}
		break;
	}

	if( !op->o_req_ndn.bv_len && default_search_nbase.bv_len ) {
		sl_free( op->o_req_dn.bv_val, op->o_tmpmemctx );
		sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );

		ber_dupbv_x( &op->o_req_dn, &default_search_base, op->o_tmpmemctx );
		ber_dupbv_x( &op->o_req_ndn, &default_search_nbase, op->o_tmpmemctx );
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	/* Sync control overrides manageDSAit */

	if ( manageDSAit != SLAP_NO_CONTROL ) {
		if ( op->o_sync_mode & SLAP_SYNC_REFRESH ) {
			be_manageDSAit = SLAP_NO_CONTROL;
		} else {
			be_manageDSAit = manageDSAit;
		}
	} else {
		be_manageDSAit = manageDSAit;
	}

	if ( (op->o_bd = select_backend( &op->o_req_ndn, be_manageDSAit, 1 )) == NULL ) {
		rs->sr_ref = referral_rewrite( default_referral,
			NULL, &op->o_req_dn, op->ors_scope );

		if (!rs->sr_ref) rs->sr_ref = default_referral;
		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		if (rs->sr_ref != default_referral)
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		goto return_results;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto return_results;
	}

	/* check for referrals */
	if( backend_check_referrals( op, rs ) != LDAP_SUCCESS ) {
		goto return_results;
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) {
		attrs = anlist2charray( op, op->ors_attrs );
		initSearchPlugin( op, attrs, manageDSAit );
		rs->sr_err = doPreSearchPluginFNs( op );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			goto return_results;
		}

		doSearchRewriteFNs( op );
	}
#endif /* LDAP_SLAPI */

	/* actually do the search and send the result(s) */
	if ( op->o_bd->be_search ) {
		(op->o_bd->be_search)( op, rs );
	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) doPostSearchPluginFNs( op );
#endif /* LDAP_SLAPI */

return_results:;

	if ( ( op->o_sync_mode & SLAP_SYNC_PERSIST ) )
		return rs->sr_err;

	if( op->o_req_dn.bv_val != NULL) sl_free( op->o_req_dn.bv_val, op->o_tmpmemctx );
	if( op->o_req_ndn.bv_val != NULL) sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );

	if( op->ors_filterstr.bv_val != NULL) op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	if( op->ors_filter != NULL) filter_free_x( op, op->ors_filter );
	if( op->ors_attrs != NULL ) op->o_tmpfree( op->ors_attrs, op->o_tmpmemctx );
#ifdef LDAP_SLAPI
	if( attrs != NULL) op->o_tmpfree( attrs, op->o_tmpmemctx );
#endif /* LDAP_SLAPI */

	return rs->sr_err;
}

#ifdef LDAP_SLAPI

static char **anlist2charray( Operation *op, AttributeName *an )
{
	char **attrs;
	int i;

	if ( an != NULL ) {
		for ( i = 0; an[i].an_name.bv_val != NULL; i++ )
			;
		attrs = (char **)op->o_tmpalloc( (i + 1) * sizeof(char *), op->o_tmpmemctx );
		for ( i = 0; an[i].an_name.bv_val != NULL; i++ ) {
			attrs[i] = an[i].an_name.bv_val;
		}
		attrs[i] = NULL;
	} else {
		attrs = NULL;
	}

	return attrs;
}

static void initSearchPlugin( Operation *op,
	char **attrs, int managedsait )
{
	slapi_x_pblock_set_operation( op->o_pb, op );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_TARGET, (void *)op->o_req_dn.bv_val );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_SCOPE, (void *)op->ors_scope );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_DEREF, (void *)op->ors_deref );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_SIZELIMIT, (void *)op->ors_slimit );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_TIMELIMIT, (void *)op->ors_tlimit );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_FILTER, (void *)op->ors_filter );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_STRFILTER, (void *)op->ors_filterstr.bv_val );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_ATTRS, (void *)attrs );
	slapi_pblock_set( op->o_pb, SLAPI_SEARCH_ATTRSONLY, (void *)op->ors_attrsonly );
	slapi_pblock_set( op->o_pb, SLAPI_MANAGEDSAIT, (void *)managedsait );
}

static int doPreSearchPluginFNs( Operation *op )
{
	int rc;

	rc = doPluginFNs( op->o_bd, SLAPI_PLUGIN_PRE_SEARCH_FN, op->o_pb );
	if ( rc < 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "doPreSearchPluginFNs: search preoperation plugin "
				"returned %d\n", rc, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "doPreSearchPluginFNs: search preoperation plugin "
				"returned %d.\n", rc, 0, 0);
#endif
		if ( ( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE, (void *)&rc ) != 0 ) ||
		     rc == LDAP_SUCCESS ) {
			rc = LDAP_OTHER;
		}
	} else {
		rc = LDAP_SUCCESS;
	}

	return rc;
}

static int doSearchRewriteFNs( Operation *op )
{
	if ( doPluginFNs( op->o_bd, SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN, op->o_pb ) == 0 ) {
		int rc;

		/*
		 * The plugin can set the SLAPI_SEARCH_FILTER.
		 * SLAPI_SEARCH_STRFILER is not normative.
		 */
		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_FILTER, (void *)&op->ors_filter );
		op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
		filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

		/*
		 * Also permit other search parameters to be reset. One thing
	 	 * this doesn't (yet) deal with is plugins that change a root
		 * DSE search to a non-root DSE search...
		 */
		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_TARGET, (void **)&op->o_req_dn.bv_val );
		op->o_req_dn.bv_len = strlen( op->o_req_dn.bv_val );

		if( op->o_req_ndn.bv_val != NULL) {
			sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );
		}
		rc = dnNormalize( 0, NULL, NULL, &op->o_req_dn, &op->o_req_ndn,
			op->o_tmpmemctx );
		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}

		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_SCOPE, (void **)&op->ors_scope );
		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_DEREF, (void **)&op->ors_deref );

#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"doSearchRewriteFNs: after compute_rewrite_search filter: %s\n", 
			op->ors_filterstr.bv_len ? op->ors_filterstr.bv_val : "empty", 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS, "    after compute_rewrite_search filter: %s\n",
			op->ors_filterstr.bv_len ? op->ors_filterstr.bv_val : "empty", 0, 0 );
#endif
	}

	return LDAP_SUCCESS;
}

static void doPostSearchPluginFNs( Operation *op )
{
	if ( doPluginFNs( op->o_bd, SLAPI_PLUGIN_POST_SEARCH_FN, op->o_pb ) < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "doPostSearchPluginFNs: search postoperation plugins "
				"failed\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "doPostSearchPluginFNs: search postoperation plugins "
				"failed.\n", 0, 0, 0);
#endif
	}
}

void dummy(void)
{
	/*
	 * XXX slapi_search_internal() was no getting pulled
	 * in; all manner of linker flags failed to link it.
	 * FIXME
	 */
	slapi_search_internal( NULL, 0, NULL, NULL, NULL, 0 );
}
#endif /* LDAP_SLAPI */


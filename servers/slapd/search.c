/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
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

#include "lutil.h"
#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"

static void init_search_pblock( Operation *op, char **attrs, int managedsait );
static int call_search_preop_plugins( Operation *op );
static int call_search_rewrite_plugins( Operation *op );
static void call_search_postop_plugins( Operation *op );
#endif /* LDAPI_SLAPI */

int
do_search(
    Operation	*op,	/* info about the op to which we're responding */
    SlapReply	*rs	/* all the response data we'll send */ )
{
	struct berval base = BER_BVNULL;
	ber_len_t	siz, off, i;

	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );

	/*
	 * Parse the search request.  It looks like this:
	 *
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree (2),
	 *          subordinate (3)  -- OpenLDAP extension
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

	if ( op->ors_tlimit < 0 || op->ors_tlimit > SLAP_MAX_LIMIT ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "invalid time limit" );
		goto return_results;
	}

	if ( op->ors_slimit < 0 || op->ors_slimit > SLAP_MAX_LIMIT ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "invalid size limit" );
		goto return_results;
	}

	switch( op->ors_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_SCOPE_SUBORDINATE
	case LDAP_SCOPE_SUBORDINATE:
#endif
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
		Debug( LDAP_DEBUG_ANY,
			"do_search: invalid dn (%s)\n", base.bv_val, 0, 0 );
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto return_results;
	}

	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d",
		base.bv_val, op->ors_scope, op->ors_deref );
	Debug( LDAP_DEBUG_ARGS, "    %d %d %d\n",
		op->ors_slimit, op->ors_tlimit, op->ors_attrsonly);

	/* filter - returns a "normalized" version */
	rs->sr_err = get_filter( op, op->o_ber, &op->ors_filter, &rs->sr_text );
	if( rs->sr_err != LDAP_SUCCESS ) {
		if( rs->sr_err == SLAPD_DISCONNECT ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			send_ldap_disconnect( op, rs );
			rs->sr_err = SLAPD_DISCONNECT;
		} else {
			send_ldap_result( op, rs );
		}
		goto return_results;
	}
	filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

	Debug( LDAP_DEBUG_ARGS, "    filter: %s\n",
		!BER_BVISEMPTY( &op->ors_filterstr ) ? op->ors_filterstr.bv_val : "empty", 0, 0 );

	/* attributes */
	siz = sizeof(AttributeName);
	off = offsetof(AttributeName,an_name);
	if ( ber_scanf( op->o_ber, "{M}}", &op->ors_attrs, &siz, off ) == LBER_ERROR ) {
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding attrs error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto return_results;
	}
	for ( i=0; i<siz; i++ ) {
		const char *dummy;	/* ignore msgs from bv2ad */
		op->ors_attrs[i].an_desc = NULL;
		op->ors_attrs[i].an_oc = NULL;
		op->ors_attrs[i].an_oc_exclude = 0;
		slap_bv2ad(&op->ors_attrs[i].an_name, &op->ors_attrs[i].an_desc, &dummy);
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_search: get_ctrls failed\n", 0, 0, 0 );

		goto return_results;
	}

	Debug( LDAP_DEBUG_ARGS, "    attrs:", 0, 0, 0 );

	if ( siz != 0 ) {
		for ( i = 0; i<siz; i++ ) {
			Debug( LDAP_DEBUG_ARGS, " %s", op->ors_attrs[i].an_name.bv_val, 0, 0 );
		}
	}

	Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );

	if ( StatslogTest( LDAP_DEBUG_STATS ) ) {
		char abuf[BUFSIZ/2], *ptr = abuf;
		int len = 0, alen;

		sprintf(abuf, "scope=%d deref=%d", op->ors_scope, op->ors_deref);
		Statslog( LDAP_DEBUG_STATS,
		        "%s SRCH base=\"%s\" %s filter=\"%s\"\n",
		        op->o_log_prefix, op->o_req_dn.bv_val, abuf,
		        op->ors_filterstr.bv_val, 0 );

		for ( i = 0; i<siz; i++ ) {
			alen = op->ors_attrs[i].an_name.bv_len;
			if (alen >= sizeof(abuf)) {
				alen = sizeof(abuf)-1;
			}
			if (len && (len + 1 + alen >= sizeof(abuf))) {
				Statslog( LDAP_DEBUG_STATS, "%s SRCH attr=%s\n",
				    op->o_log_prefix, abuf, 0, 0, 0 );
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
			Statslog( LDAP_DEBUG_STATS, "%s SRCH attr=%s\n",
	    			op->o_log_prefix, abuf, 0, 0, 0 );
		}
	}

	op->o_bd = frontendDB;
	rs->sr_err = frontendDB->be_search( op, rs );

return_results:;
	if ( ( op->o_sync_mode & SLAP_SYNC_PERSIST ) ) {
		return rs->sr_err;
	}
	if ( ( op->o_sync_slog_size != -1 ) ) {
		return rs->sr_err;
	}
	if ( !BER_BVISNULL( &op->o_req_dn ) ) {
		slap_sl_free( op->o_req_dn.bv_val, op->o_tmpmemctx );
	}
	if ( !BER_BVISNULL( &op->o_req_ndn ) ) {
		slap_sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	}
	if ( !BER_BVISNULL( &op->ors_filterstr ) ) {
		op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	}
	if ( op->ors_filter != NULL) {
		filter_free_x( op, op->ors_filter );
	}
	if ( op->ors_attrs != NULL ) {
		op->o_tmpfree( op->ors_attrs, op->o_tmpmemctx );
	}

	return rs->sr_err;
}

int
fe_op_search( Operation *op, SlapReply *rs )
{
	int			manageDSAit;
	int			be_manageDSAit;
#ifdef LDAP_SLAPI
	char			**attrs = NULL;
#endif

	manageDSAit = get_manageDSAit( op );

	/* fake while loop to allow breaking out */
	while ( op->ors_scope == LDAP_SCOPE_BASE ) {
		Entry *entry = NULL;

		if ( BER_BVISEMPTY( &op->o_req_ndn ) ) {
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
				attrs = anlist2charray_x( op->ors_attrs, 0, op->o_tmpmemctx );
				init_search_pblock( op, attrs, manageDSAit );
				rs->sr_err = call_search_preop_plugins( op );
				if ( rs->sr_err ) break;
				call_search_rewrite_plugins( op );
			}
#endif /* LDAP_SLAPI */
			rs->sr_err = root_dse_info( op->o_conn, &entry, &rs->sr_text );

		} else if ( bvmatch( &op->o_req_ndn, &frontendDB->be_schemandn ) ) {
			/* check restrictions */
			if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				goto return_results;
			}

#ifdef LDAP_SLAPI
			if ( op->o_pb ) {
				attrs = anlist2charray_x( op->ors_attrs, 0, op->o_tmpmemctx );
				init_search_pblock( op, attrs, manageDSAit );
				rs->sr_err = call_search_preop_plugins( op );
				if ( rs->sr_err ) break;
				call_search_rewrite_plugins( op );
			}
#endif /* LDAP_SLAPI */
			rs->sr_err = schema_info( &entry, &rs->sr_text );
		}

		if( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
#ifdef LDAP_SLAPI
			if ( op->o_pb ) call_search_postop_plugins( op );
#endif /* LDAP_SLAPI */
			goto return_results;

		} else if ( entry != NULL ) {
			rs->sr_err = test_filter( op, entry, op->ors_filter );

			if( rs->sr_err == LDAP_COMPARE_TRUE ) {
				rs->sr_entry = entry;
				rs->sr_attrs = op->ors_attrs;
				rs->sr_operational_attrs = NULL;
				send_search_entry( op, rs );
				rs->sr_entry = NULL;
				rs->sr_operational_attrs = NULL;
			}
			entry_free( entry );

			rs->sr_err = LDAP_SUCCESS;
			send_ldap_result( op, rs );
#ifdef LDAP_SLAPI
			if ( op->o_pb ) call_search_postop_plugins( op );
#endif /* LDAP_SLAPI */
			goto return_results;
		}
		break;
	}

	if( BER_BVISEMPTY( &op->o_req_ndn ) && !BER_BVISEMPTY( &default_search_nbase ) ) {
		slap_sl_free( op->o_req_dn.bv_val, op->o_tmpmemctx );
		slap_sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );

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

	op->o_bd = select_backend( &op->o_req_ndn, be_manageDSAit, 1 );
	if ( op->o_bd == NULL ) {
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
		attrs = anlist2charray_x( op->ors_attrs, 0, op->o_tmpmemctx );
		init_search_pblock( op, attrs, manageDSAit );
		rs->sr_err = call_search_preop_plugins( op );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			goto return_results;
		}

		call_search_rewrite_plugins( op );
	}
#endif /* LDAP_SLAPI */

	/* actually do the search and send the result(s) */
	if ( op->o_bd->be_search ) {
		if ( limits_check( op, rs ) == 0 ) {
			(op->o_bd->be_search)( op, rs );
		}
		/* else limits_check() sends error */

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) call_search_postop_plugins( op );
#endif /* LDAP_SLAPI */

#ifdef LDAP_SLAPI
	if( attrs != NULL) op->o_tmpfree( attrs, op->o_tmpmemctx );
#endif /* LDAP_SLAPI */

return_results:;
	return rs->sr_err;
}

#ifdef LDAP_SLAPI

static void init_search_pblock( Operation *op,
	char **attrs, int managedsait )
{
	slapi_int_pblock_set_operation( op->o_pb, op );
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

static int call_search_preop_plugins( Operation *op )
{
	int rc;

	rc = slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_PRE_SEARCH_FN, op->o_pb );
	if ( rc < 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
		Debug(LDAP_DEBUG_TRACE, "call_search_preop_plugins: search preoperation plugin "
				"returned %d.\n", rc, 0, 0);
		if ( ( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE, (void *)&rc ) != 0 ) ||
		     rc == LDAP_SUCCESS ) {
			rc = LDAP_OTHER;
		}
	} else {
		rc = LDAP_SUCCESS;
	}

	return rc;
}

static int call_search_rewrite_plugins( Operation *op )
{
	if ( slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN, op->o_pb ) == 0 ) {
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

		if( !BER_BVISNULL( &op->o_req_ndn ) ) {
			slap_sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );
		}
		rc = dnNormalize( 0, NULL, NULL, &op->o_req_dn, &op->o_req_ndn,
			op->o_tmpmemctx );
		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}

		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_SCOPE, (void **)&op->ors_scope );
		slapi_pblock_get( op->o_pb, SLAPI_SEARCH_DEREF, (void **)&op->ors_deref );

		Debug( LDAP_DEBUG_ARGS, "    after compute_rewrite_search filter: %s\n",
			!BER_BVISEMPTY( &op->ors_filterstr ) ? op->ors_filterstr.bv_val : "empty", 0, 0 );
	}

	return LDAP_SUCCESS;
}

static void call_search_postop_plugins( Operation *op )
{
	if ( slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_POST_SEARCH_FN, op->o_pb ) < 0 ) {
		Debug(LDAP_DEBUG_TRACE, "call_search_postop_plugins: search postoperation plugins "
				"failed.\n", 0, 0, 0);
	}
}

void slapi_int_dummy(void)
{
	/*
	 * XXX slapi_search_internal() was no getting pulled
	 * in; all manner of linker flags failed to link it.
	 * FIXME
	 */
	slapi_search_internal( NULL, 0, NULL, NULL, NULL, 0 );
}
#endif /* LDAP_SLAPI */


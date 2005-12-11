/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "ldap_log.h"
#include "../../../libraries/libldap/ldap-int.h"

static int
meta_send_entry(
	Operation 	*op,
	SlapReply	*rs,
	metaconn_t	*mc,
	int 		i,
	LDAPMessage 	*e );

typedef enum meta_search_candidate_t {
	META_SEARCH_ERR = -1,
	META_SEARCH_NOT_CANDIDATE,
	META_SEARCH_CANDIDATE
} meta_search_candidate_t;

static meta_search_candidate_t
meta_back_search_start(
	Operation		*op,
	SlapReply		*rs,
	dncookie		*dc,
	metasingleconn_t	*msc,
	int			candidate,
	SlapReply		*candidates
)
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	struct berval	realbase = op->o_req_dn;
	int		realscope = op->ors_scope;
	ber_len_t	suffixlen = 0;
	struct berval	mbase = BER_BVNULL; 
	struct berval	mfilter = BER_BVNULL;
	char		**mapped_attrs = NULL;
	int		rc;
	meta_search_candidate_t	retcode;
	struct timeval	tv, *tvp = NULL;

	/* should we check return values? */
	if ( op->ors_deref != -1 ) {
		ldap_set_option( msc->msc_ld, LDAP_OPT_DEREF,
				( void * )&op->ors_deref );
	}

	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		tv.tv_sec = op->ors_tlimit > 0 ? op->ors_tlimit : 1;
		tvp = &tv;
	}

	dc->target = &mi->mi_targets[ candidate ];

	/*
	 * modifies the base according to the scope, if required
	 */
	suffixlen = mi->mi_targets[ candidate ].mt_nsuffix.bv_len;
	if ( suffixlen > op->o_req_ndn.bv_len ) {
		switch ( op->ors_scope ) {
		case LDAP_SCOPE_SUBTREE:
			/*
			 * make the target suffix the new base
			 * FIXME: this is very forgiving, because
			 * "illegal" searchBases may be turned
			 * into the suffix of the target; however,
			 * the requested searchBase already passed
			 * thru the candidate analyzer...
			 */
			if ( dnIsSuffix( &mi->mi_targets[ candidate ].mt_nsuffix,
					&op->o_req_ndn ) )
			{
				realbase = mi->mi_targets[ candidate ].mt_nsuffix;
				if ( mi->mi_targets[ candidate ].mt_scope == LDAP_SCOPE_SUBORDINATE ) {
					realscope = LDAP_SCOPE_SUBORDINATE;
				}

			} else {
				/*
				 * this target is no longer candidate
				 */
				return META_SEARCH_NOT_CANDIDATE;
			}
			break;

		case LDAP_SCOPE_SUBORDINATE:
		case LDAP_SCOPE_ONELEVEL:
		{
			struct berval	rdn = mi->mi_targets[ candidate ].mt_nsuffix;
			rdn.bv_len -= op->o_req_ndn.bv_len + STRLENOF( "," );
			if ( dnIsOneLevelRDN( &rdn )
					&& dnIsSuffix( &mi->mi_targets[ candidate ].mt_nsuffix, &op->o_req_ndn ) )
			{
				/*
				 * if there is exactly one level,
				 * make the target suffix the new
				 * base, and make scope "base"
				 */
				realbase = mi->mi_targets[ candidate ].mt_nsuffix;
				if ( op->ors_scope == LDAP_SCOPE_SUBORDINATE ) {
					if ( mi->mi_targets[ candidate ].mt_scope == LDAP_SCOPE_SUBORDINATE ) {
						realscope = LDAP_SCOPE_SUBORDINATE;
					} else {
						realscope = LDAP_SCOPE_SUBTREE;
					}
				} else {
					realscope = LDAP_SCOPE_BASE;
				}
				break;
			} /* else continue with the next case */
		}

		case LDAP_SCOPE_BASE:
			/*
			 * this target is no longer candidate
			 */
			return META_SEARCH_NOT_CANDIDATE;
		}
	}

	/*
	 * Rewrite the search base, if required
	 */
	dc->ctx = "searchBase";
	switch ( ldap_back_dn_massage( dc, &realbase, &mbase ) ) {
	default:
		break;

	case REWRITE_REGEXEC_UNWILLING:
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "Operation not allowed";
		send_ldap_result( op, rs );
		return META_SEARCH_ERR;

	case REWRITE_REGEXEC_ERR:

		/*
		 * this target is no longer candidate
		 */
		return META_SEARCH_NOT_CANDIDATE;
	}

	/*
	 * Maps filter
	 */
	rc = ldap_back_filter_map_rewrite( dc, op->ors_filter,
			&mfilter, BACKLDAP_MAP );
	switch ( rc ) {
	case LDAP_SUCCESS:
		break;

	case LDAP_COMPARE_FALSE:
	default:
		/*
		 * this target is no longer candidate
		 */
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto done;
	}

	/*
	 * Maps required attributes
	 */
	rc = ldap_back_map_attrs( &mi->mi_targets[ candidate ].mt_rwmap.rwm_at,
			op->ors_attrs, BACKLDAP_MAP, &mapped_attrs );
	if ( rc != LDAP_SUCCESS ) {
		/*
		 * this target is no longer candidate
		 */
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto done;
	}

	/*
	 * Starts the search
	 */
	rc = ldap_search_ext( msc->msc_ld,
			mbase.bv_val, realscope, mfilter.bv_val,
			mapped_attrs, op->ors_attrsonly,
			op->o_ctrls, NULL, tvp, op->ors_slimit,
			&candidates[ candidate ].sr_msgid ); 
	if ( rc == LDAP_SUCCESS ) {
		retcode = META_SEARCH_CANDIDATE;

	} else {
		candidates[ candidate ].sr_msgid = -1;
		retcode = META_SEARCH_NOT_CANDIDATE;
	}

done:;
	if ( mapped_attrs ) {
		free( mapped_attrs );
	}
	if ( mfilter.bv_val != op->ors_filterstr.bv_val ) {
		free( mfilter.bv_val );
	}
	if ( mbase.bv_val != realbase.bv_val ) {
		free( mbase.bv_val );
	}

	return retcode;
}

int
meta_back_search( Operation *op, SlapReply *rs )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t	*mc;
	struct timeval	tv = { 0, 0 };
	time_t		stoptime = (time_t)-1;
	LDAPMessage	*res = NULL, *e;
	int		rc = 0, sres = LDAP_SUCCESS;
	char		*matched = NULL;
	int		last = 0, ncandidates = 0,
			initial_candidates = 0, candidate_match = 0;
	long		i;
	dncookie	dc;
	int		is_ok = 0;
	void		*savepriv;
	SlapReply	*candidates = meta_back_candidates_get( op );

	/*
	 * controls are set in ldap_back_dobind()
	 * 
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */
	mc = meta_back_getconn( op, rs, NULL, LDAP_BACK_SENDERR );
	if ( !mc || !meta_back_dobind( op, rs, mc, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}

	dc.conn = op->o_conn;
	dc.rs = rs;

	/*
	 * Inits searches
	 */
	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		metasingleconn_t	*msc = &mc->mc_conns[ i ];

		candidates[ i ].sr_msgid = -1;
		candidates[ i ].sr_matched = NULL;
		candidates[ i ].sr_text = NULL;
		candidates[ i ].sr_ref = NULL;
		candidates[ i ].sr_ctrls = NULL;

		if ( candidates[ i ].sr_tag != META_CANDIDATE
			|| candidates[ i ].sr_err != LDAP_SUCCESS )
		{
			continue;
		}

		switch ( meta_back_search_start( op, rs, &dc, msc, i, candidates ) )
		{
		case META_SEARCH_NOT_CANDIDATE:
			break;

		case META_SEARCH_CANDIDATE:
			candidates[ i ].sr_type = REP_INTERMEDIATE;
			++ncandidates;
			break;

		case META_SEARCH_ERR:
			rc = -1;
			goto finish;
		}
	}

	initial_candidates = ncandidates;

#if 0
	{
		char	cnd[BUFSIZ];
		int	i;

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( candidates[ i ].sr_tag == META_CANDIDATE ) {
				cnd[ i ] = '*';
			} else {
				cnd[ i ] = ' ';
			}
		}
		cnd[ i ] = '\0';

		Debug( LDAP_DEBUG_ANY, "%s meta_back_search: ncandidates=%d "
			"cnd=\"%s\"\n", op->o_log_prefix, ncandidates, cnd );
	}
#endif

	if ( initial_candidates == 0 ) {
		/* NOTE: here we are not sending any matchedDN;
		 * this is intended, because if the back-meta
		 * is serving this search request, but no valid
		 * candidate could be looked up, it means that
		 * there is a hole in the mapping of the targets
		 * and thus no knowledge of any remote superior
		 * is available */
		Debug( LDAP_DEBUG_ANY, "%s meta_back_search: "
			"base=\"%s\" scope=%d: "
			"no candidate could be selected\n",
			op->o_log_prefix, op->o_req_dn.bv_val,
			op->ors_scope );

		/* FIXME: we're sending the first error we encounter;
		 * maybe we should pick the worst... */
		rc = LDAP_NO_SUCH_OBJECT;
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( candidates[ i ].sr_tag == META_CANDIDATE
				&& candidates[ i ].sr_err != LDAP_SUCCESS )
			{
				rc = candidates[ i ].sr_err;
				break;
			}
		}

		send_ldap_error( op, rs, rc, NULL );

		goto finish;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */

	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		stoptime = op->o_time + op->ors_tlimit;
	}

	/*
	 * In case there are no candidates, no cycle takes place...
	 *
	 * FIXME: we might use a queue, to better balance the load 
	 * among the candidates
	 */
	for ( rc = 0; ncandidates > 0; ) {
		int	gotit = 0, doabandon = 0;

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			metasingleconn_t	*msc = &mc->mc_conns[ i ];

			if ( candidates[ i ].sr_msgid == -1 ) {
				continue;
			}

			/* check for abandon */
			if ( op->o_abandon ) {
				break;
			}
			
			/*
			 * FIXME: handle time limit as well?
			 * Note that target servers are likely 
			 * to handle it, so at some time we'll
			 * get a LDAP_TIMELIMIT_EXCEEDED from
			 * one of them ...
			 */
get_result:;
			rc = ldap_result( msc->msc_ld, candidates[ i ].sr_msgid,
					0, &tv, &res );

			if ( rc == 0 ) {
				/* FIXME: res should not need to be freed */
				assert( res == NULL );

				/* check time limit */
				if ( op->ors_tlimit != SLAP_NO_LIMIT
						&& slap_get_time() > stoptime )
				{
					doabandon = 1;
					rc = rs->sr_err = LDAP_TIMELIMIT_EXCEEDED;
					savepriv = op->o_private;
					op->o_private = (void *)i;
					send_ldap_result( op, rs );
					op->o_private = savepriv;
					goto finish;
				}

				continue;

			} else if ( rc == -1 ) {
really_bad:;
				/* something REALLY bad happened! */
				if ( candidates[ i ].sr_type == REP_INTERMEDIATE ) {
					candidates[ i ].sr_type = REP_RESULT;

					if ( meta_back_retry( op, rs, mc, i, LDAP_BACK_DONTSEND ) ) {
						switch ( meta_back_search_start( op, rs, &dc, msc, i, candidates ) )
						{
						case META_SEARCH_CANDIDATE:
							goto get_result;

						default:
							rc = rs->sr_err = LDAP_OTHER;
							goto finish;
						}
					}
				}

				/*
				 * When no candidates are left,
				 * the outer cycle finishes
				 */
				candidates[ i ].sr_msgid = -1;
				--ncandidates;
				rs->sr_err = candidates[ i ].sr_err = LDAP_OTHER;
				rs->sr_text = "remote server unavailable";

			} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
				if ( candidates[ i ].sr_type == REP_INTERMEDIATE ) {
					/* don't retry any more... */
					candidates[ i ].sr_type = REP_RESULT;
				}

				is_ok++;

				e = ldap_first_entry( msc->msc_ld, res );
				savepriv = op->o_private;
				op->o_private = (void *)i;
				rs->sr_err = meta_send_entry( op, rs, mc, i, e );
				ldap_msgfree( res );
				res = NULL;

				switch ( rs->sr_err ) {
				case LDAP_SIZELIMIT_EXCEEDED:
					savepriv = op->o_private;
					op->o_private = (void *)i;
					send_ldap_result( op, rs );
					op->o_private = savepriv;
					rs->sr_err = LDAP_SUCCESS;
					goto finish;

				case LDAP_UNAVAILABLE:
					rs->sr_err = LDAP_OTHER;
					goto finish;
				}
				op->o_private = savepriv;

				gotit = 1;

#if 0
				/*
				 * If scope is BASE, we need to jump out
				 * as soon as one entry is found; if
				 * the target pool is properly crafted,
				 * this should correspond to the sole
				 * entry that has the base DN
				 */
				/* FIXME: this defeats the purpose of
				 * doing a search with scope == base and
				 * sizelimit = 1 to determine if a
				 * candidate is actually unique */
				if ( op->ors_scope == LDAP_SCOPE_BASE
						&& rs->sr_nentries > 0 )
				{
					doabandon = 1;
					ncandidates = 0;
					sres = LDAP_SUCCESS;
					break;
				}
#endif

			} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
				char		**references = NULL;
				int		cnt;

				if ( candidates[ i ].sr_type == REP_INTERMEDIATE ) {
					/* don't retry any more... */
					candidates[ i ].sr_type = REP_RESULT;
				}

				is_ok++;

				rc = ldap_parse_reference( msc->msc_ld, res,
						&references, &rs->sr_ctrls, 1 );
				res = NULL;

				if ( rc != LDAP_SUCCESS ) {
					continue;
				}

				if ( references == NULL ) {
					continue;
				}

#ifdef ENABLE_REWRITE
				dc.ctx = "referralDN";
#else /* ! ENABLE_REWRITE */
				dc.tofrom = 0;
				dc.normalized = 0;
#endif /* ! ENABLE_REWRITE */

				/* FIXME: merge all and return at the end */

				for ( cnt = 0; references[ cnt ]; cnt++ )
					;

				rs->sr_ref = ch_calloc( sizeof( struct berval ), cnt + 1 );

				for ( cnt = 0; references[ cnt ]; cnt++ ) {
					ber_str2bv( references[ cnt ], 0, 1, &rs->sr_ref[ cnt ] );
				}
				BER_BVZERO( &rs->sr_ref[ cnt ] );

				( void )ldap_back_referral_result_rewrite( &dc, rs->sr_ref );

				if ( rs->sr_ref != NULL && !BER_BVISNULL( &rs->sr_ref[ 0 ] ) ) {
					/* ignore return value by now */
					savepriv = op->o_private;
					op->o_private = (void *)i;
					( void )send_search_reference( op, rs );
					op->o_private = savepriv;

					ber_bvarray_free( rs->sr_ref );
					rs->sr_ref = NULL;
				}

				/* cleanup */
				if ( references ) {
					ber_memvfree( (void **)references );
				}

				if ( rs->sr_ctrls ) {
					ldap_controls_free( rs->sr_ctrls );
					rs->sr_ctrls = NULL;
				}

			} else if ( rc == LDAP_RES_SEARCH_RESULT ) {
				char		buf[ SLAP_TEXT_BUFLEN ];
				char		**references = NULL;

				if ( candidates[ i ].sr_type == REP_INTERMEDIATE ) {
					/* don't retry any more... */
					candidates[ i ].sr_type = REP_RESULT;
				}

				if ( ldap_parse_result( msc->msc_ld,
							res,
							&candidates[ i ].sr_err,
							(char **)&candidates[ i ].sr_matched,
							NULL /* (char **)&candidates[ i ].sr_text */ ,
							&references,
							&candidates[ i ].sr_ctrls, 1 ) != LDAP_SUCCESS )
				{
					res = NULL;
					ldap_get_option( msc->msc_ld,
							LDAP_OPT_ERROR_NUMBER,
							&rs->sr_err );
					sres = slap_map_api2result( rs );
					candidates[ i ].sr_type = REP_RESULT;
					goto really_bad;
				}

				rs->sr_err = candidates[ i ].sr_err;
				sres = slap_map_api2result( rs );
				res = NULL;

				/* massage matchedDN if need be */
				if ( candidates[ i ].sr_matched != NULL ) {
#ifndef LDAP_NULL_IS_NULL
					if ( candidates[ i ].sr_matched[ 0 ] == '\0' ) {
						ldap_memfree( (char *)candidates[ i ].sr_matched );
						candidates[ i ].sr_matched = NULL;

					} else
#endif /* LDAP_NULL_IS_NULL */
					{
						struct berval	match, mmatch;

						ber_str2bv( candidates[ i ].sr_matched,
							0, 0, &match );
						candidates[ i ].sr_matched = NULL;

						dc.ctx = "matchedDN";
						dc.target = &mi->mi_targets[ i ];
						if ( !ldap_back_dn_massage( &dc, &match, &mmatch ) ) {
							if ( mmatch.bv_val == match.bv_val ) {
								candidates[ i ].sr_matched = ch_strdup( mmatch.bv_val );

							} else {
								candidates[ i ].sr_matched = mmatch.bv_val;
							}

							candidate_match++;
						} 
						ldap_memfree( match.bv_val );
					}
				}

#ifndef LDAP_NULL_IS_NULL
				/* just get rid of the error message, if any */
				if ( candidates[ i ].sr_text && candidates[ i ].sr_text[ 0 ] == '\0' )
				{
					ldap_memfree( (char *)candidates[ i ].sr_text );
					candidates[ i ].sr_text = NULL;
				}
#endif /* LDAP_NULL_IS_NULL */

				/* add references to array */
				if ( references ) {
					BerVarray	sr_ref;
					int		cnt;

					for ( cnt = 0; references[ cnt ]; cnt++ )
						;

					sr_ref = ch_calloc( sizeof( struct berval ), cnt + 1 );

					for ( cnt = 0; references[ cnt ]; cnt++ ) {
						ber_str2bv( references[ cnt ], 0, 1, &sr_ref[ cnt ] );
					}
					BER_BVZERO( &sr_ref[ cnt ] );

					( void )ldap_back_referral_result_rewrite( &dc, sr_ref );
				
					/* cleanup */
					ber_memvfree( (void **)references );

					if ( rs->sr_v2ref == NULL ) {
						rs->sr_v2ref = sr_ref;

					} else {
						for ( cnt = 0; !BER_BVISNULL( &sr_ref[ cnt ] ); cnt++ ) {
							ber_bvarray_add( &rs->sr_v2ref, &sr_ref[ cnt ] );
						}
						ber_memfree( sr_ref );
					}
				}

				rs->sr_err = candidates[ i ].sr_err;
				sres = slap_map_api2result( rs );

				snprintf( buf, sizeof( buf ),
					"%s meta_back_search[%ld] "
					"match=\"%s\" err=%ld\n",
					op->o_log_prefix, i,
					candidates[ i ].sr_matched ? candidates[ i ].sr_matched : "",
					(long) candidates[ i ].sr_err );
				Debug( LDAP_DEBUG_ANY, "%s", buf, 0, 0 );

				switch ( sres ) {
				case LDAP_NO_SUCH_OBJECT:
					/* is_ok is touched any time a valid
					 * (even intermediate) result is
					 * returned; as a consequence, if
					 * a candidate returns noSuchObject
					 * it is ignored and the candidate
					 * is simply demoted. */
					if ( is_ok ) {
						sres = LDAP_SUCCESS;
					}
					break;

				case LDAP_SUCCESS:
				case LDAP_REFERRAL:
					is_ok++;
					break;

				default:
					if ( META_BACK_ONERR_STOP( mi ) ) {
						savepriv = op->o_private;
						op->o_private = (void *)i;
						send_ldap_result( op, rs );
						op->o_private = savepriv;
						goto finish;
					}
					break;
				}

				last = i;
				rc = 0;

				/*
				 * When no candidates are left,
				 * the outer cycle finishes
				 */
				candidates[ i ].sr_msgid = -1;
				--ncandidates;

			} else {
				assert( 0 );
				goto really_bad;
			}
		}

		/* check for abandon */
		if ( op->o_abandon || doabandon ) {
			for ( i = 0; i < mi->mi_ntargets; i++ ) {
				metasingleconn_t	*msc = &mc->mc_conns[ i ];

				if ( candidates[ i ].sr_msgid != -1 ) {
					ldap_abandon_ext( msc->msc_ld,
						candidates[ i ].sr_msgid,
						NULL, NULL );
					candidates[ i ].sr_msgid = -1;
				}
			}

			if ( op->o_abandon ) {
				rc = SLAPD_ABANDON;
				goto finish;
			}
		}

		if ( gotit == 0 ) {
			LDAP_BACK_TV_SET( &tv );
                        ldap_pvt_thread_yield();

		} else {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		}
	}

	if ( rc == -1 ) {
		/*
		 * FIXME: need a better strategy to handle errors
		 */
		rc = meta_back_op_result( mc, op, rs, META_TARGET_NONE );
		goto finish;
	}

	/*
	 * Rewrite the matched portion of the search base, if required
	 * 
	 * FIXME: only the last one gets caught!
	 */
	savepriv = op->o_private;
	op->o_private = (void *)(long)mi->mi_ntargets;
	if ( candidate_match > 0 ) {
		struct berval	pmatched = BER_BVNULL;

		/* we use the first one */
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( candidates[ i ].sr_tag == META_CANDIDATE
					&& candidates[ i ].sr_matched != NULL )
			{
				struct berval	bv, pbv;
				int		rc;

				/* if we got success, and this target
				 * returned noSuchObject, and its suffix
				 * is a superior of the searchBase,
				 * ignore the matchedDN */
				if ( sres == LDAP_SUCCESS
					&& candidates[ i ].sr_err == LDAP_NO_SUCH_OBJECT
					&& op->o_req_ndn.bv_len > mi->mi_targets[ i ].mt_nsuffix.bv_len )
				{
					free( (char *)candidates[ i ].sr_matched );
					candidates[ i ].sr_matched = NULL;
					continue;
				}

				ber_str2bv( candidates[ i ].sr_matched, 0, 0, &bv );
				rc = dnPretty( NULL, &bv, &pbv, op->o_tmpmemctx );

				if ( rc == LDAP_SUCCESS ) {

					/* NOTE: if they all are superiors
					 * of the baseDN, the shorter is also 
					 * superior of the longer... */
					if ( pbv.bv_len > pmatched.bv_len ) {
						if ( !BER_BVISNULL( &pmatched ) ) {
							op->o_tmpfree( pmatched.bv_val, op->o_tmpmemctx );
						}
						pmatched = pbv;
						op->o_private = (void *)i;

					} else {
						op->o_tmpfree( pbv.bv_val, op->o_tmpmemctx );
					}
				}

				if ( candidates[ i ].sr_matched != NULL ) {
					free( (char *)candidates[ i ].sr_matched );
					candidates[ i ].sr_matched = NULL;
				}
			}
		}

		if ( !BER_BVISNULL( &pmatched ) ) {
			matched = pmatched.bv_val;
		}

	} else if ( sres == LDAP_NO_SUCH_OBJECT ) {
		matched = op->o_bd->be_suffix[ 0 ].bv_val;
	}

#if 0
	{
		char	buf[BUFSIZ];
		char	cnd[BUFSIZ];
		int	i;

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( candidates[ i ].sr_tag == META_CANDIDATE ) {
				cnd[ i ] = '*';
			} else {
				cnd[ i ] = ' ';
			}
		}
		cnd[ i ] = '\0';

		snprintf( buf, sizeof( buf ), "%s meta_back_search: is_scope=%d is_ok=%d cnd=\"%s\"\n",
			op->o_log_prefix, initial_candidates, is_ok, cnd );

		Debug( LDAP_DEBUG_ANY, "%s", buf, 0, 0 );
	}
#endif

	/*
	 * In case we returned at least one entry, we return LDAP_SUCCESS
	 * otherwise, the latter error code we got
	 *
	 * FIXME: we should handle error codes and return the more 
	 * important/reasonable
	 */

	if ( sres == LDAP_SUCCESS && rs->sr_v2ref ) {
		sres = LDAP_REFERRAL;
	}
	rs->sr_err = sres;
	rs->sr_matched = matched;
	rs->sr_ref = ( sres == LDAP_REFERRAL ? rs->sr_v2ref : NULL );
	send_ldap_result( op, rs );
	op->o_private = savepriv;
	rs->sr_matched = NULL;
	rs->sr_ref = NULL;

finish:;
	if ( matched && matched != op->o_bd->be_suffix[ 0 ].bv_val ) {
		op->o_tmpfree( matched, op->o_tmpmemctx );
	}

	if ( rs->sr_v2ref ) {
		ber_bvarray_free( rs->sr_v2ref );
	}

	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		if ( candidates[ i ].sr_tag != META_CANDIDATE ) {
			continue;
		}

		if ( candidates[ i ].sr_matched ) {
			free( (char *)candidates[ i ].sr_matched );
			candidates[ i ].sr_matched = NULL;
		}

		if ( candidates[ i ].sr_text ) {
			ldap_memfree( (char *)candidates[ i ].sr_text );
			candidates[ i ].sr_text = NULL;
		}

		if ( candidates[ i ].sr_ref ) {
			ber_bvarray_free( candidates[ i ].sr_ref );
			candidates[ i ].sr_ref = NULL;
		}

		if ( candidates[ i ].sr_ctrls ) {
			ldap_controls_free( candidates[ i ].sr_ctrls );
			candidates[ i ].sr_ctrls = NULL;
		}
	}

	meta_back_release_conn( op, mc );

	return rs->sr_err;
}

static int
meta_send_entry(
	Operation 	*op,
	SlapReply	*rs,
	metaconn_t	*mc,
	int 		target,
	LDAPMessage 	*e )
{
	metainfo_t 		*mi = ( metainfo_t * )op->o_bd->be_private;
	struct berval		a, mapped;
	Entry 			ent = { 0 };
	BerElement 		ber = *e->lm_ber;
	Attribute 		*attr, **attrp;
	struct berval 		bdn,
				dn = BER_BVNULL;
	const char 		*text;
	dncookie		dc;
	int			rc;

	if ( ber_scanf( &ber, "{m{", &bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
	}

	/*
	 * Rewrite the dn of the result, if needed
	 */
	dc.target = &mi->mi_targets[ target ];
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "searchResult";

	rs->sr_err = ldap_back_dn_massage( &dc, &bdn, &dn );
	if ( rs->sr_err != LDAP_SUCCESS) {
		return rs->sr_err;
	}

	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 * 
	 * FIXME: should we log anything, or delegate to dnNormalize?
	 */
	rc = dnPrettyNormal( NULL, &dn, &ent.e_name, &ent.e_nname,
		op->o_tmpmemctx );
	if ( dn.bv_val != bdn.bv_val ) {
		free( dn.bv_val );
	}
	BER_BVZERO( &dn );

	if ( rc != LDAP_SUCCESS ) {
		return LDAP_INVALID_DN_SYNTAX;
	}

	/*
	 * cache dn
	 */
	if ( mi->mi_cache.ttl != META_DNCACHE_DISABLED ) {
		( void )meta_dncache_update_entry( &mi->mi_cache,
				&ent.e_nname, target );
	}

	attrp = &ent.e_attrs;

	dc.ctx = "searchAttrDN";
	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		int				last = 0;
		slap_syntax_validate_func	*validate;
		slap_syntax_transform_func	*pretty;

		ldap_back_map( &mi->mi_targets[ target ].mt_rwmap.rwm_at, 
				&a, &mapped, BACKLDAP_REMAP );
		if ( BER_BVISNULL( &mapped ) || mapped.bv_val[0] == '\0' ) {
			( void )ber_scanf( &ber, "x" /* [W] */ );
			continue;
		}
		attr = ( Attribute * )ch_calloc( 1, sizeof( Attribute ) );
		if ( attr == NULL ) {
			continue;
		}
		if ( slap_bv2ad( &mapped, &attr->a_desc, &text )
				!= LDAP_SUCCESS) {
			if ( slap_bv2undef_ad( &mapped, &attr->a_desc, &text,
				SLAP_AD_PROXIED ) != LDAP_SUCCESS )
			{
				char	buf[ SLAP_TEXT_BUFLEN ];

				snprintf( buf, sizeof( buf ),
					"%s meta_send_entry(\"%s\"): "
					"slap_bv2undef_ad(%s): %s\n",
					op->o_log_prefix, ent.e_name.bv_val,
					mapped.bv_val, text );

				Debug( LDAP_DEBUG_ANY, "%s", buf, 0, 0 );
				ch_free( attr );
				continue;
			}
		}

		/* no subschemaSubentry */
		if ( attr->a_desc == slap_schema.si_ad_subschemaSubentry
			|| attr->a_desc == slap_schema.si_ad_entryDN )
		{

			/* 
			 * We eat target's subschemaSubentry because
			 * a search for this value is likely not
			 * to resolve to the appropriate backend;
			 * later, the local subschemaSubentry is
			 * added.
			 *
			 * We also eat entryDN because the frontend
			 * will reattach it without checking if already
			 * present...
			 */
			( void )ber_scanf( &ber, "x" /* [W] */ );

			ch_free(attr);
			continue;
		}

		if ( ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR 
				|| attr->a_vals == NULL )
		{
			attr->a_vals = (struct berval *)&slap_dummy_bv;

		} else {
			for ( last = 0; !BER_BVISNULL( &attr->a_vals[ last ] ); ++last )
				;
		}

		validate = attr->a_desc->ad_type->sat_syntax->ssyn_validate;
		pretty = attr->a_desc->ad_type->sat_syntax->ssyn_pretty;

		if ( !validate && !pretty ) {
			attr_free( attr );
			goto next_attr;
		}

		if ( attr->a_desc == slap_schema.si_ad_objectClass
				|| attr->a_desc == slap_schema.si_ad_structuralObjectClass )
		{
			struct berval 	*bv;

			for ( bv = attr->a_vals; !BER_BVISNULL( bv ); bv++ ) {
				ldap_back_map( &mi->mi_targets[ target ].mt_rwmap.rwm_oc,
						bv, &mapped, BACKLDAP_REMAP );
				if ( BER_BVISNULL( &mapped ) || mapped.bv_val[0] == '\0') {
					free( bv->bv_val );
					BER_BVZERO( bv );
					if ( --last < 0 ) {
						break;
					}
					*bv = attr->a_vals[ last ];
					BER_BVZERO( &attr->a_vals[ last ] );
					bv--;

				} else if ( mapped.bv_val != bv->bv_val ) {
					free( bv->bv_val );
					ber_dupbv( bv, &mapped );
				}
			}
		/*
		 * It is necessary to try to rewrite attributes with
		 * dn syntax because they might be used in ACLs as
		 * members of groups; since ACLs are applied to the
		 * rewritten stuff, no dn-based subecj clause could
		 * be used at the ldap backend side (see
		 * http://www.OpenLDAP.org/faq/data/cache/452.html)
		 * The problem can be overcome by moving the dn-based
		 * ACLs to the target directory server, and letting
		 * everything pass thru the ldap backend.
		 */
		} else {
			int	i;

			if ( attr->a_desc->ad_type->sat_syntax ==
				slap_schema.si_syn_distinguishedName )
			{
				ldap_dnattr_result_rewrite( &dc, attr->a_vals );

			} else if ( attr->a_desc == slap_schema.si_ad_ref ) {
				ldap_back_referral_result_rewrite( &dc, attr->a_vals );

			}

			for ( i = 0; i < last; i++ ) {
				struct berval	pval;
				int		rc;

				if ( pretty ) {
					rc = pretty( attr->a_desc->ad_type->sat_syntax,
						&attr->a_vals[i], &pval, NULL );

				} else {
					rc = validate( attr->a_desc->ad_type->sat_syntax,
						&attr->a_vals[i] );
				}

				if ( rc ) {
					LBER_FREE( attr->a_vals[i].bv_val );
					if ( --last == i ) {
						BER_BVZERO( &attr->a_vals[ i ] );
						break;
					}
					attr->a_vals[i] = attr->a_vals[last];
					BER_BVZERO( &attr->a_vals[last] );
					i--;
					continue;
				}

				if ( pretty ) {
					LBER_FREE( attr->a_vals[i].bv_val );
					attr->a_vals[i] = pval;
				}
			}

			if ( last == 0 && attr->a_vals != &slap_dummy_bv ) {
				attr_free( attr );
				goto next_attr;
			}
		}

		if ( last && attr->a_desc->ad_type->sat_equality &&
			attr->a_desc->ad_type->sat_equality->smr_normalize )
		{
			int i;

			attr->a_nvals = ch_malloc( ( last + 1 ) * sizeof( struct berval ) );
			for ( i = 0; i<last; i++ ) {
				attr->a_desc->ad_type->sat_equality->smr_normalize(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					attr->a_desc->ad_type->sat_syntax,
					attr->a_desc->ad_type->sat_equality,
					&attr->a_vals[i], &attr->a_nvals[i],
					NULL );
			}
			BER_BVZERO( &attr->a_nvals[i] );

		} else {
			attr->a_nvals = attr->a_vals;
		}

		*attrp = attr;
		attrp = &attr->a_next;
next_attr:;
	}
	rs->sr_entry = &ent;
	rs->sr_attrs = op->ors_attrs;
	rs->sr_flags = 0;
	rc = send_search_entry( op, rs );
	switch ( rc ) {
	case LDAP_UNAVAILABLE:
		rc = LDAP_OTHER;
		break;
	}
	rs->sr_entry = NULL;
	rs->sr_attrs = NULL;
	
	if ( !BER_BVISNULL( &ent.e_name ) ) {
		free( ent.e_name.bv_val );
		BER_BVZERO( &ent.e_name );
	}
	if ( !BER_BVISNULL( &ent.e_nname ) ) {
		free( ent.e_nname.bv_val );
		BER_BVZERO( &ent.e_nname );
	}
	entry_clean( &ent );

	return rc;
}


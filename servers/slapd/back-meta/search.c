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

static int
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
	struct berval		realbase = op->o_req_dn;
	int			realscope = op->ors_scope;
	ber_len_t		suffixlen = 0;
	struct berval		mbase = BER_BVNULL; 
	struct berval		mfilter = BER_BVNULL;
	char			**mapped_attrs = NULL;
	int			rc;

	/* should we check return values? */
	if ( op->ors_deref != -1 ) {
		ldap_set_option( msc->msc_ld, LDAP_OPT_DEREF,
				( void * )&op->ors_deref);
	}
	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		ldap_set_option( msc->msc_ld, LDAP_OPT_TIMELIMIT,
				( void * )&op->ors_tlimit);
	}
	if ( op->ors_slimit != SLAP_NO_LIMIT ) {
		ldap_set_option( msc->msc_ld, LDAP_OPT_SIZELIMIT,
				( void * )&op->ors_slimit);
	}

	dc->rwmap = &mi->mi_targets[ candidate ]->mt_rwmap;

	/*
	 * modifies the base according to the scope, if required
	 */
	suffixlen = mi->mi_targets[ candidate ]->mt_nsuffix.bv_len;
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
			if ( dnIsSuffix( &mi->mi_targets[ candidate ]->mt_nsuffix,
					&op->o_req_ndn ) )
			{
				realbase = mi->mi_targets[ candidate ]->mt_nsuffix;

			} else {
				/*
				 * this target is no longer candidate
				 */
				return 0;
			}
			break;

		case LDAP_SCOPE_ONELEVEL:
		{
			struct berval	rdn = mi->mi_targets[ candidate ]->mt_nsuffix;
			rdn.bv_len -= op->o_req_ndn.bv_len + STRLENOF( "," );
			if ( dnIsOneLevelRDN( &rdn )
					&& dnIsSuffix( &mi->mi_targets[ candidate ]->mt_nsuffix, &op->o_req_ndn ) )
			{
				/*
				 * if there is exactly one level,
				 * make the target suffix the new
				 * base, and make scope "base"
				 */
				realbase = mi->mi_targets[ candidate ]->mt_nsuffix;
				realscope = LDAP_SCOPE_BASE;
				break;
			} /* else continue with the next case */
		}

		case LDAP_SCOPE_BASE:
			/*
			 * this target is no longer candidate
			 */
			return 0;
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
		return -1;

	case REWRITE_REGEXEC_ERR:

		/*
		 * this target is no longer candidate
		 */
		return 0;
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
		rc = 0;
		goto done;
	}

	/*
	 * Maps required attributes
	 */
	rc = ldap_back_map_attrs( &mi->mi_targets[ candidate ]->mt_rwmap.rwm_at,
			op->ors_attrs, BACKLDAP_MAP, &mapped_attrs );
	if ( rc != LDAP_SUCCESS ) {
		/*
		 * this target is no longer candidate
		 */
		rc = 0;
		goto done;
	}

	/*
	 * Starts the search
	 */
	rc = ldap_search_ext( msc->msc_ld,
			mbase.bv_val, realscope, mfilter.bv_val,
			mapped_attrs, op->ors_attrsonly,
			op->o_ctrls, NULL, NULL, op->ors_slimit,
			&candidates[ candidate ].sr_msgid ); 
	if ( rc == LDAP_SUCCESS ) {
		rc = 1;

	} else {
		candidates[ candidate ].sr_msgid = -1;
		rc = 0;
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

	return rc;
}

int
meta_back_search( Operation *op, SlapReply *rs )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t		*mc;
	metasingleconn_t	*msc;
	struct timeval		tv = { 0, 0 };
	LDAPMessage		*res = NULL, *e;
	int			rc = 0, sres = LDAP_SUCCESS;
	BerVarray		refs = NULL, v2refs = NULL;
	char			*matched = NULL;
	int			i, last = 0, ncandidates = 0,
				initial_candidates = 0, candidate_match = 0;
	dncookie		dc;
	int			is_ok = 0;
	void			*savepriv;
	SlapReply		*candidates = meta_back_candidates_get( op );

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
	for ( i = 0, msc = &mc->mc_conns[ 0 ]; !META_LAST( msc ); ++i, ++msc ) {
		candidates[ i ].sr_msgid = -1;

		if ( candidates[ i ].sr_tag != META_CANDIDATE ) {
			continue;
		}
		candidates[ i ].sr_err = LDAP_SUCCESS;
		candidates[ i ].sr_matched = NULL;
		candidates[ i ].sr_text = NULL;
		candidates[ i ].sr_ref = NULL;
		candidates[ i ].sr_ctrls = NULL;

		switch ( meta_back_search_start( op, rs, &dc, msc, i, candidates ) )
		{
		case 0:
			break;

		case 1:
			++ncandidates;
			break;

		case -1:
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
		send_ldap_error( op, rs, LDAP_NO_SUCH_OBJECT, NULL );
		/* FIXME: find a way to look up the best match */

		rc = LDAP_NO_SUCH_OBJECT;
		goto finish;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */

	/*
	 * In case there are no candidates, no cycle takes place...
	 *
	 * FIXME: we might use a queue, to better balance the load 
	 * among the candidates
	 */
	for ( rc = 0; ncandidates > 0; ) {
		int	gotit = 0, doabandon = 0;

		for ( i = 0, msc = &mc->mc_conns[ 0 ]; !META_LAST( msc ); msc++, i++ ) {
			if ( candidates[ i ].sr_msgid == -1 ) {
				continue;
			}

			/* check for abandon */
			if ( op->o_abandon ) {
				break;
			}
			
			if ( op->ors_slimit > 0 && rs->sr_nentries == op->ors_slimit )
			{
				rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
				rs->sr_v2ref = v2refs;
				savepriv = op->o_private;
				op->o_private = (void *)i;
				send_ldap_result( op, rs );
				op->o_private = savepriv;
				goto finish;
			}

			/*
			 * FIXME: handle time limit as well?
			 * Note that target servers are likely 
			 * to handle it, so at some time we'll
			 * get a LDAP_TIMELIMIT_EXCEEDED from
			 * one of them ...
			 */
			rc = ldap_result( msc->msc_ld, candidates[ i ].sr_msgid,
					0, &tv, &res );

			if ( rc == 0 ) {
				/* timeout exceeded */

				/* FIXME: res should not need to be freed */
				assert( res == NULL );

				continue;

			} else if ( rc == -1 ) {
really_bad:;
				/* something REALLY bad happened! */
				( void )meta_clear_unused_candidates( op, -1 );
				rs->sr_err = LDAP_OTHER;
				rs->sr_v2ref = v2refs;
				savepriv = op->o_private;
				op->o_private = (void *)i;
				send_ldap_result( op, rs );
				op->o_private = savepriv;
				rs->sr_v2ref = NULL;
				
				/* anything else needs be done? */

				/* FIXME: res should not need to be freed */
				assert( res == NULL );

				goto finish;

			} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
				is_ok++;

				e = ldap_first_entry( msc->msc_ld, res );
				savepriv = op->o_private;
				op->o_private = (void *)i;
				meta_send_entry( op, rs, mc, i, e );
				op->o_private = savepriv;

				ldap_msgfree( res );
				res = NULL;

				/*
				 * If scope is BASE, we need to jump out
				 * as soon as one entry is found; if
				 * the target pool is properly crafted,
				 * this should correspond to the sole
				 * entry that has the base DN
				 */
				if ( op->ors_scope == LDAP_SCOPE_BASE
						&& rs->sr_nentries > 0 )
				{
					doabandon = 1;
					ncandidates = 0;
					sres = LDAP_SUCCESS;
					break;
				}

				gotit = 1;

			} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
				char		**references = NULL;
				int		cnt;

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
					ldap_value_free( references );
				}

				if ( rs->sr_ctrls ) {
					ldap_controls_free( rs->sr_ctrls );
					rs->sr_ctrls = NULL;
				}

			} else if ( rc == LDAP_RES_SEARCH_RESULT ) {
				char		buf[ SLAP_TEXT_BUFLEN ];
				char		**references = NULL;

				if ( ldap_parse_result( msc->msc_ld,
							res,
							&candidates[ i ].sr_err,
							(char **)&candidates[ i ].sr_matched,
							NULL /* (char **)&candidates[ i ].sr_text */ ,
							&references,
							&candidates[ i ].sr_ctrls, 1 ) )
				{
					res = NULL;
					ldap_get_option( msc->msc_ld,
							LDAP_OPT_ERROR_NUMBER,
							&rs->sr_err );
					sres = slap_map_api2result( rs );
					goto really_bad;
				}
				rs->sr_err = candidates[ i ].sr_err;
				sres = slap_map_api2result( rs );
				res = NULL;

				/* massage matchedDN if need be */
				if ( candidates[ i ].sr_matched != NULL ) {
					if ( candidates[ i ].sr_matched[ 0 ] == '\0' ) {
						ldap_memfree( (char *)candidates[ i ].sr_matched );
						candidates[ i ].sr_matched = NULL;

					} else {
						struct berval	match, mmatch;

						ber_str2bv( candidates[ i ].sr_matched,
							0, 0, &match );

						dc.ctx = "matchedDN";
						dc.rwmap = &mi->mi_targets[ i ]->mt_rwmap;

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

				/* just get rid of the error message, if any */
				if ( candidates[ i ].sr_text && candidates[ i ].sr_text[ 0 ] == '\0' )
				{
					ldap_memfree( (char *)candidates[ i ].sr_text );
					candidates[ i ].sr_text = NULL;
				}

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
					ldap_value_free( references );

					if ( refs == NULL ) {
						refs = sr_ref;

					} else {
						for ( cnt = 0; !BER_BVISNULL( &sr_ref[ cnt ] ); cnt++ ) {
							ber_bvarray_add( &refs, &sr_ref[ cnt ] );
						}
						ber_memfree( sr_ref );
					}
				}

				rs->sr_err = candidates[ i ].sr_err;
				sres = slap_map_api2result( rs );
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
					is_ok++;
					break;
				}

				snprintf( buf, sizeof( buf ),
					"%s meta_back_search[%d] "
					"match=\"%s\" err=%d\n",
					op->o_log_prefix, i,
					candidates[ i ].sr_matched ? candidates[ i ].sr_matched : "",
					candidates[ i ].sr_err );
				Debug( LDAP_DEBUG_ANY, "%s", buf, 0, 0 );

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
			for ( i = 0, msc = mc->mc_conns; !META_LAST( msc ); msc++, i++ ) {
				if ( candidates[ i ].sr_msgid != -1 ) {
					ldap_abandon_ext( msc->msc_ld,
						candidates[ i ].sr_msgid,
						NULL, NULL );
				}
			}

			if ( op->o_abandon ) {
				rc = SLAPD_ABANDON;
				goto finish;
			}
		}

		if ( gotit == 0 ) {
			tv.tv_sec = 0;
                        tv.tv_usec = 100000;	/* 0.1 s */
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
	if ( candidate_match > 0 && rs->sr_nentries > 0 ) {
		/* we use the first one */
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( candidates[ i ].sr_tag == META_CANDIDATE
					&& candidates[ i ].sr_matched )
			{
				matched = (char *)candidates[ i ].sr_matched;
				candidates[ i ].sr_matched = NULL;
				break;
			}
		}
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

	if ( sres == LDAP_SUCCESS && ( v2refs || refs ) ) {
		sres = LDAP_REFERRAL;
	}
	rs->sr_err = sres;
	rs->sr_matched = matched;
	rs->sr_v2ref = v2refs;
	rs->sr_ref = refs;
	savepriv = op->o_private;
	op->o_private = (void *)mi->mi_ntargets;
	send_ldap_result( op, rs );
	op->o_private = savepriv;
	rs->sr_matched = NULL;
	rs->sr_v2ref = NULL;
	rs->sr_ref = NULL;

finish:;
	if ( matched ) {
		free( matched );
	}

	if ( refs ) {
		ber_bvarray_free( refs );
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

	return rc;
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
	struct berval 		*bv, bdn;
	const char 		*text;
	dncookie		dc;

	if ( ber_scanf( &ber, "{m{", &bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
	}

	/*
	 * Rewrite the dn of the result, if needed
	 */
	dc.rwmap = &mi->mi_targets[ target ]->mt_rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "searchResult";

	rs->sr_err = ldap_back_dn_massage( &dc, &bdn, &ent.e_name );
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
	if ( dnNormalize( 0, NULL, NULL, &ent.e_name, &ent.e_nname,
		op->o_tmpmemctx ) != LDAP_SUCCESS )
	{
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
		int		last = 0;

		ldap_back_map( &mi->mi_targets[ target ]->mt_rwmap.rwm_at, 
				&a, &mapped, BACKLDAP_REMAP );
		if ( BER_BVISNULL( &mapped ) || mapped.bv_val[0] == '\0' ) {
			continue;
		}
		attr = ( Attribute * )ch_malloc( sizeof( Attribute ) );
		if ( attr == NULL ) {
			continue;
		}
		attr->a_flags = 0;
		attr->a_next = 0;
		attr->a_desc = NULL;
		if ( slap_bv2ad( &mapped, &attr->a_desc, &text )
				!= LDAP_SUCCESS) {
			if ( slap_bv2undef_ad( &mapped, &attr->a_desc, &text ) 
					!= LDAP_SUCCESS )
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
		if ( attr->a_desc == slap_schema.si_ad_subschemaSubentry ) {

			/* 
			 * We eat target's subschemaSubentry because
			 * a search for this value is likely not
			 * to resolve to the appropriate backend;
			 * later, the local subschemaSubentry is
			 * added.
			 */
			( void )ber_scanf( &ber, "x" /* [W] */ );

			ch_free(attr);
			continue;
		}

		if ( ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR 
				|| attr->a_vals == NULL ) {
			attr->a_vals = (struct berval *)&slap_dummy_bv;

		} else if ( attr->a_desc == slap_schema.si_ad_objectClass
				|| attr->a_desc == slap_schema.si_ad_structuralObjectClass ) {

			for ( last = 0; !BER_BVISNULL( &attr->a_vals[ last ] ); ++last );

			for ( bv = attr->a_vals; !BER_BVISNULL( bv ); bv++ ) {
				ldap_back_map( &mi->mi_targets[ target ]->mt_rwmap.rwm_oc,
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
		} else if ( attr->a_desc->ad_type->sat_syntax ==
				slap_schema.si_syn_distinguishedName )
		{
			ldap_dnattr_result_rewrite( &dc, attr->a_vals );

		} else if ( attr->a_desc == slap_schema.si_ad_ref ) {
			ldap_back_referral_result_rewrite( &dc, attr->a_vals );
		}

		if ( last && attr->a_desc->ad_type->sat_equality &&
			attr->a_desc->ad_type->sat_equality->smr_normalize ) {
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
	}
	rs->sr_entry = &ent;
	rs->sr_attrs = op->ors_attrs;
	rs->sr_flags = 0;
	send_search_entry( op, rs );
	rs->sr_entry = NULL;
	rs->sr_attrs = NULL;
	while ( ent.e_attrs ) {
		attr = ent.e_attrs;
		ent.e_attrs = attr->a_next;
		if ( attr->a_vals != &slap_dummy_bv ) {
			if ( attr->a_nvals != attr->a_vals ) {
				ber_bvarray_free( attr->a_nvals );
			}
			ber_bvarray_free( attr->a_vals );
		}
		free( attr );
	}
	
	if ( ent.e_dn && ent.e_dn != bdn.bv_val ) {
		free( ent.e_dn );
	}
	if ( ent.e_ndn ) {
		free( ent.e_ndn );
	}

	return LDAP_SUCCESS;
}


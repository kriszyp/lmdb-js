/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This work has been developed to fulfill the requirements
 * of SysNet s.n.c. <http:www.sys-net.it> and it has been donated
 * to the OpenLDAP Foundation in the hope that it may be useful
 * to the Open Source community, but WITHOUT ANY WARRANTY.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from 
 *    flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 *
 * 4. This notice may not be removed or altered.
 *
 *
 * This software is based on the backend back-ldap, implemented
 * by Howard Chu <hyc@highlandsun.com>, and modified by Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. The contribution of the original software to the present
 * implementation is acknowledged in this copyright statement.
 *
 * A special acknowledgement goes to Howard for the overall architecture
 * (and for borrowing large pieces of code), and to Mark, who implemented
 * from scratch the attribute/objectclass mapping.
 *
 * The original copyright statement follows.
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the
 *    documentation.
 *
 * 4. This notice may not be removed or altered.
 *                
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#include "ldap_pvt.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "ldap_log.h"
#include "../../../libraries/libldap/ldap-int.h"

static int
meta_send_entry(
		Operation 	*op,
		SlapReply	*rs,
		struct metaconn	*lc,
		int 		i,
		LDAPMessage 	*e
);

static int
is_one_level_rdn(
		const char	*rdn,
		int		from
);

int
meta_back_search( Operation *op, SlapReply *rs )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn *lc;
	struct metasingleconn *lsc;
	struct timeval	tv = { 0, 0 };
	LDAPMessage	*res, *e;
	int	count, rc = 0, *msgid, sres = LDAP_NO_SUCH_OBJECT;
	char *match = NULL, *err = NULL;
	char *mmatch = NULL;
	BerVarray v2refs = NULL;
		
	int i, last = 0, candidates = 0;
	struct slap_limits_set *limit = NULL;
	int isroot = 0;

#ifdef LDAP_CACHING
	cache_manager*  cm = li->cm;

 	if (cm->caching) {
 		return meta_back_cache_search(op->o_bd, op->o_conn, op,
				&op->o_req_dn, &op->o_req_ndn, 
				op->oq_search.rs_scope,
				op->oq_search.rs_deref,
				op->oq_search.rs_slimit,
				op->oq_search.rs_tlimit,
				op->oq_search.rs_filter,
				&op->oq_search.rs_filterstr,
				op->oq_search.rs_attrs,
				op->oq_search.rs_attrsonly); 
	}
#endif /* LDAP_CACHING */
	
	/*
	 * controls are set in ldap_back_dobind()
	 * 
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */
	lc = meta_back_getconn( op, rs, META_OP_ALLOW_MULTIPLE, 
			&op->o_req_ndn, NULL );
	if ( !lc ) {
 		send_ldap_result( op, rs );
		return -1;
	}

	if ( !meta_back_dobind( lc, op ) ) {
		rs->sr_err = LDAP_OTHER;
 		send_ldap_result( op, rs );
		return -1;
	}

	/*
	 * Array of message id of each target
	 */
	msgid = ch_calloc( sizeof( int ), li->ntargets );
	if ( msgid == NULL ) {
		rs->sr_err = LDAP_OTHER;
 		send_ldap_result( op, rs );
		return -1;
	}
	
	/* if not root, get appropriate limits */
	if ( be_isroot( op->o_bd, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( op->o_bd, &op->o_ndn, &limit );
	}

	/* if no time limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && op->oq_search.rs_tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0
				&& limit->lms_t_soft > -1
				&& op->oq_search.rs_tlimit > limit->lms_t_soft ) {
			op->oq_search.rs_tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
			send_ldap_result( op, rs );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}
	
	/* if no size limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && op->oq_search.rs_slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0
				&& limit->lms_s_soft > -1
				&& op->oq_search.rs_slimit > limit->lms_s_soft ) {
			op->oq_search.rs_slimit = limit->lms_s_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
			send_ldap_result( op, rs );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}

	/*
	 * Inits searches
	 */
	for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
		char		*realbase = ( char * )op->o_req_dn.bv_val;
		int		realscope = op->oq_search.rs_scope;
		ber_len_t	suffixlen = 0;
		char		*mbase = NULL; 
		struct berval	mfilter = { 0L, NULL };
		char		**mapped_attrs = NULL;

		if ( lsc->candidate != META_CANDIDATE ) {
			msgid[ i ] = -1;
			continue;
		}

		/* should we check return values? */
		if ( op->oq_search.rs_deref != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_DEREF,
					( void * )&op->oq_search.rs_deref);
		}
		if ( op->oq_search.rs_tlimit != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_TIMELIMIT,
					( void * )&op->oq_search.rs_tlimit);
		}
		if ( op->oq_search.rs_slimit != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_SIZELIMIT,
					( void * )&op->oq_search.rs_slimit);
		}

		/*
		 * modifies the base according to the scope, if required
		 */
		suffixlen = li->targets[ i ]->suffix.bv_len;
		if ( suffixlen > op->o_req_ndn.bv_len ) {
			switch ( op->oq_search.rs_scope ) {
			case LDAP_SCOPE_SUBTREE:
				/*
				 * make the target suffix the new base
				 * FIXME: this is very forgiving, because
				 * illegal bases may be turned into 
				 * the suffix of the target.
				 */
				if ( dnIsSuffix( &li->targets[ i ]->suffix,
						&op->o_req_ndn ) ) {
					realbase = li->targets[ i ]->suffix.bv_val;
				} else {
					/*
					 * this target is no longer candidate
					 */
					msgid[ i ] = -1;
					goto new_candidate;
				}
				break;

			case LDAP_SCOPE_ONELEVEL:
				if ( is_one_level_rdn( li->targets[ i ]->suffix.bv_val,
						suffixlen - op->o_req_ndn.bv_len - 1 ) 
			&& dnIsSuffix( &li->targets[ i ]->suffix, &op->o_req_ndn ) ) {
					/*
					 * if there is exactly one level,
					 * make the target suffix the new
					 * base, and make scope "base"
					 */
					realbase = li->targets[ i ]->suffix.bv_val;
					realscope = LDAP_SCOPE_BASE;
					break;
				} /* else continue with the next case */

			case LDAP_SCOPE_BASE:
				/*
				 * this target is no longer candidate
				 */
				msgid[ i ] = -1;
				goto new_candidate;
			}

		}

		/*
		 * Rewrite the search base, if required
		 */
	 	switch ( rewrite_session( li->targets[ i ]->rwinfo,
					"searchBase",
 					realbase, op->o_conn, &mbase ) ) {
		case REWRITE_REGEXEC_OK:
		if ( mbase == NULL ) {
			mbase = realbase;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"[rw] searchBase [%d]: \"%s\" -> \"%s\"\n",
			i, op->o_req_dn.bv_val, mbase );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> searchBase [%d]: \"%s\" -> \"%s\"\n",
				i, op->o_req_dn.bv_val, mbase );
#endif /* !NEW_LOGGING */
		break;
		
		case REWRITE_REGEXEC_UNWILLING:
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "Operation not allowed";
			send_ldap_result( op, rs );
			rc = -1;
			goto finish;

		case REWRITE_REGEXEC_ERR:
#if 0
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "Rewrite error";
			send_ldap_result( op, rs );
			rc = -1;
			goto finish;
#endif 

			/*
			 * this target is no longer candidate
			 */
			msgid[ i ] = -1;
			goto new_candidate;
		}

		/*
		 * Maps filter
		 */
		rc = ldap_back_filter_map_rewrite_( li->targets[ i ]->rwinfo,
				op->o_conn,
				&li->targets[ i ]->at_map,
				&li->targets[ i ]->oc_map, 
				op->oq_search.rs_filter,
				&mfilter, BACKLDAP_MAP );
		if ( rc != 0 ) {
			/*
			 * this target is no longer candidate
			 */
			msgid[ i ] = -1;
			goto new_candidate;
		}

		/*
		 * Maps required attributes
		 */
		rc = ldap_back_map_attrs( &li->targets[ i ]->at_map,
				op->oq_search.rs_attrs, BACKLDAP_MAP,
				&mapped_attrs );
		if ( rc != LDAP_SUCCESS ) {
			/*
			 * this target is no longer candidate
			 */
			msgid[ i ] = -1;
			goto new_candidate;
		}

#if 0
		if ( mapped_attrs == NULL && op->oq_search.rs_attrs) {
			for ( count = 0; op->oq_search.rs_attrs[ count ].an_name.bv_val; count++ );
			mapped_attrs = ch_malloc( ( count + 1 ) * sizeof(char *));
			for ( count = 0; op->oq_search.rs_attrs[ count ].an_name.bv_val; count++ ) {
				mapped_attrs[ count ] = op->oq_search.rs_attrs[ count ].an_name.bv_val;
			}
			mapped_attrs[ count ] = NULL;
		}
#endif

		/*
		 * Starts the search
		 */
		msgid[ i ] = ldap_search( lsc->ld, mbase, realscope,
				mfilter.bv_val, mapped_attrs,
				op->oq_search.rs_attrsonly ); 
		if ( mapped_attrs ) {
			free( mapped_attrs );
			mapped_attrs = NULL;
		}
		if ( mfilter.bv_val != op->oq_search.rs_filterstr.bv_val ) {
			free( mfilter.bv_val );
			mfilter.bv_val = NULL;
		}
		if ( mbase != realbase ) {
			free( mbase );
			mbase = NULL;
		}

		if ( msgid[ i ] == -1 ) {
			continue;
		}

		++candidates;

new_candidate:;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */


	/*
	 * In case there are no candidates, no cycle takes place...
	 *
	 * FIXME: we might use a queue, to balance the load 
	 * among the candidates
	 */
	for ( rc = 0; candidates > 0; ) {
		int ab, gotit = 0;

		/* check for abandon */
		ab = op->o_abandon;

		for ( i = 0, lsc = lc->conns; !META_LAST(lsc); lsc++, i++ ) {
			if ( msgid[ i ] == -1 ) {
				continue;
			}
			
			if ( ab ) {
				ldap_abandon( lsc->ld, msgid[ i ] );
				rc = 0;
				break;
			}

			if ( op->oq_search.rs_slimit > 0
					&& rs->sr_nentries == op->oq_search.rs_slimit ) {
				rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
				rs->sr_v2ref = v2refs;
				send_ldap_result( op, rs );
				goto finish;
			}

			/*
			 * FIXME: handle time limit as well?
			 * Note that target servers are likely 
			 * to handle it, so at some time we'll
			 * get a LDAP_TIMELIMIT_EXCEEDED from
			 * one of them ...
			 */
			rc = ldap_result( lsc->ld, msgid[ i ],
					0, &tv, &res );

			if ( rc == 0 ) {
				continue;

			} else if ( rc == -1 ) {
				/* something REALLY bad happened! */
				( void )meta_clear_unused_candidates( li,
						lc, -1, 0 );
				rs->sr_err = LDAP_OTHER;
				rs->sr_v2ref = v2refs;
				send_ldap_result( op, rs );
				
				/* anything else needs be done? */
				goto finish;

			} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
				e = ldap_first_entry( lsc->ld, res );
				meta_send_entry( op, rs, lc, i, e );

				/*
				 * If scope is BASE, we need to jump out
				 * as soon as one entry is found; if
				 * the target pool is properly crafted,
				 * this should correspond to the sole
				 * entry that has the base DN
				 */
				if ( op->oq_search.rs_scope == LDAP_SCOPE_BASE
						&& rs->sr_nentries > 0 ) {
					candidates = 0;
					sres = LDAP_SUCCESS;
					break;
				}
				ldap_msgfree( res );
				gotit = 1;

			} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
				char		**references = NULL;
				int		cnt;

				/*
				 * FIXME: should we collect references
				 * and send them alltogether at the end?
				 */

				rc = ldap_parse_reference( lsc->ld, res,
						&references, &rs->sr_ctrls, 1 );

				if ( rc != LDAP_SUCCESS ) {
					continue;
				}

				if ( references == NULL ) {
					continue;
				}

				for ( cnt = 0; references[ cnt ]; cnt++ )
					/* NO OP */ ;
				
				rs->sr_ref = ch_calloc( cnt + 1, sizeof( struct berval ) );

				for ( cnt = 0; references[ cnt ]; cnt++ ) {
					rs->sr_ref[ cnt ].bv_val = references[ cnt ];
					rs->sr_ref[ cnt ].bv_len = strlen( references[ cnt ] );
				}

				/* ignore return value by now */
				( void )send_search_reference( op, rs );

				/* cleanup */
				if ( references ) {
					ldap_value_free( references );
					ch_free( rs->sr_ref );
					rs->sr_ref = NULL;
				}

				if ( rs->sr_ctrls ) {
					ldap_controls_free( rs->sr_ctrls );
					rs->sr_ctrls = NULL;
				}

			} else {
				rs->sr_err = ldap_result2error( lsc->ld,
						res, 1 );
				sres = ldap_back_map_result( rs );
				if ( err != NULL ) {
					free( err );
				}
				ldap_get_option( lsc->ld,
						LDAP_OPT_ERROR_STRING, &err );
				if ( match != NULL ) {
					free( match );
				}
				ldap_get_option( lsc->ld,
						LDAP_OPT_MATCHED_DN, &match );

#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, ERR,
					"meta_back_search [%d] "
					"match=\"%s\" err=\"%s\"\n",
					i, match, err );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY,
					"=>meta_back_search [%d] "
					"match=\"%s\" err=\"%s\"\n",
     					i, match, err );	
#endif /* !NEW_LOGGING */
				
				last = i;
				rc = 0;

				/*
				 * When no candidates are left,
				 * the outer cycle finishes
				 */
				msgid[ i ] = -1;
				--candidates;
			}
		}

		if ( ab ) {
			goto finish;
		}

		if ( gotit == 0 ) {
			tv.tv_sec = 0;
                        tv.tv_usec = 100000;
                        ldap_pvt_thread_yield();
		} else {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		}
	}

	if ( rc == -1 ) {
		/*
		 * FIXME: need a strategy to handle errors
		 */
		rc = meta_back_op_result( lc, op, rs );
		goto finish;
	}

	/*
	 * Rewrite the matched portion of the search base, if required
	 * 
	 * FIXME: only the last one gets caught!
	 */
	if ( match != NULL ) {
		switch ( rewrite_session( li->targets[ last ]->rwinfo,
					"matchedDn", match, op->o_conn,
					&mmatch ) ) {
		case REWRITE_REGEXEC_OK:
			if ( mmatch == NULL ) {
				mmatch = ( char * )match;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"[rw] matchedDn: \"%s\" -> \"%s\"\n",
				match, mmatch, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS,
				"rw> matchedDn: \"%s\" -> \"%s\"\n",
				match, mmatch, 0 );
#endif /* !NEW_LOGGING */
			break;
			
		case REWRITE_REGEXEC_UNWILLING:
			
		case REWRITE_REGEXEC_ERR:
			/* FIXME: no error, but no matched ... */
			mmatch = NULL;
			break;
		}
	}

	/*
	 * In case we returned at least one entry, we return LDAP_SUCCESS
	 * otherwise, the latter error code we got
	 *
	 * FIXME: we should handle error codes and return the more 
	 * important/reasonable
	 */
	if ( sres == LDAP_SUCCESS && v2refs ) {
		sres = LDAP_REFERRAL;
	}
	rs->sr_err = sres;
	rs->sr_matched = mmatch;
	rs->sr_v2ref = v2refs;
	send_ldap_result( op, rs );
	rs->sr_matched = NULL;
	rs->sr_v2ref = NULL;


finish:;
	if ( match ) {
		if ( mmatch != match ) {
			free( mmatch );
		}
		free(match);
	}
	
	if ( err ) {
		free( err );
	}
	
	if ( msgid ) {
		ch_free( msgid );
	}

	return rc;
}

static int
meta_send_entry(
		Operation 	*op,
		SlapReply	*rs,
		struct metaconn *lc,
		int 		target,
		LDAPMessage 	*e
)
{
	struct metainfo 	*li = ( struct metainfo * )op->o_bd->be_private;
	struct berval		a, mapped;
	Entry 			ent;
	BerElement 		ber = *e->lm_ber;
	Attribute 		*attr, **attrp;
	struct berval 		dummy = { 0, NULL };
	struct berval 		*bv, bdn;
	const char 		*text;

	if ( ber_scanf( &ber, "{m{", &bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
	}

	/*
	 * Rewrite the dn of the result, if needed
	 */
	switch ( rewrite_session( li->targets[ target ]->rwinfo,
				"searchResult", bdn.bv_val, lc->conn,
				&ent.e_name.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( ent.e_name.bv_val == NULL ) {
			ent.e_name = bdn;

		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"[rw] searchResult[%d]: \"%s\" -> \"%s\"\n",
				target, bdn.bv_val, ent.e_name.bv_val );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> searchResult[%d]: \"%s\""
 					" -> \"%s\"\n", target, bdn.bv_val,
					ent.e_name.bv_val );
#endif /* !NEW_LOGGING */
			ent.e_name.bv_len = strlen( ent.e_name.bv_val );
		}
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		return LDAP_UNWILLING_TO_PERFORM;

	case REWRITE_REGEXEC_ERR:
		return LDAP_OTHER;
	}

	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 * 
	 * FIXME: should we log anything, or delegate to dnNormalize2?
	 */
	if ( dnNormalize2( NULL, &ent.e_name, &ent.e_nname ) != LDAP_SUCCESS ) {
		return LDAP_INVALID_DN_SYNTAX;
	}

	/*
	 * cache dn
	 */
	if ( li->cache.ttl != META_DNCACHE_DISABLED ) {
		( void )meta_dncache_update_entry( &li->cache,
						   &ent.e_nname,
						   target );
	}

	ent.e_id = 0;
	ent.e_attrs = 0;
	ent.e_private = 0;
	attrp = &ent.e_attrs;

	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		ldap_back_map( &li->targets[ target ]->at_map, 
				&a, &mapped, BACKLDAP_REMAP );
		if ( mapped.bv_val == NULL || mapped.bv_val[0] == '\0' ) {
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
					!= LDAP_SUCCESS) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1,
					"slap_bv2undef_ad(%s): %s\n", mapped.bv_val, text, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY,
						"slap_bv2undef_ad(%s): "
						"%s\n%s", mapped.bv_val, text, "" );
#endif /* !NEW_LOGGING */
				ch_free( attr );
				continue;
			}
		}

		/* no subschemaSubentry */
		if ( attr->a_desc == slap_schema.si_ad_subschemaSubentry ) {
			ch_free(attr);
			continue;
		}

		if ( ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR 
				|| attr->a_vals == NULL ) {
			attr->a_vals = &dummy;

		} else if ( attr->a_desc == slap_schema.si_ad_objectClass
				|| attr->a_desc == slap_schema.si_ad_structuralObjectClass ) {
			int		last;

			for ( last = 0; attr->a_vals[ last ].bv_val; ++last );

			for ( bv = attr->a_vals; bv->bv_val; bv++ ) {
				ldap_back_map( &li->targets[ target]->oc_map,
						bv, &mapped, BACKLDAP_REMAP );
				if ( mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
					free( bv->bv_val );
					bv->bv_val = NULL;
					if ( --last < 0 ) {
						break;
					}
					*bv = attr->a_vals[ last ];
					attr->a_vals[ last ].bv_val = NULL;
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
		} else if ( strcmp( attr->a_desc->ad_type->sat_syntax->ssyn_oid,
					SLAPD_DN_SYNTAX ) == 0 ) {
			int		last;

			for ( last = 0; attr->a_vals[ last ].bv_val; ++last );

			for ( bv = attr->a_vals; bv->bv_val; bv++ ) {
				char *newval;

				switch ( rewrite_session( li->targets[ target ]->rwinfo,
							"searchResult",
							bv->bv_val,
							lc->conn, &newval )) {
				case REWRITE_REGEXEC_OK:
					/* left as is */
					if ( newval == NULL ) {
						break;
					}
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"[rw] searchResult on attr=%s: \"%s\" -> \"%s\"\n",
						attr->a_desc->ad_type->sat_cname.bv_val,
						bv->bv_val, newval );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ARGS,
						"rw> searchResult on attr=%s:"
						" \"%s\" -> \"%s\"\n",
					attr->a_desc->ad_type->sat_cname.bv_val,
						bv->bv_val, newval );
#endif /* !NEW_LOGGING */
					free( bv->bv_val );
					bv->bv_val = newval;
					bv->bv_len = strlen( newval );

					break;

				case REWRITE_REGEXEC_UNWILLING:
					LBER_FREE(bv->bv_val);
					bv->bv_val = NULL;
					if (--last < 0)
						goto next_attr;
					*bv = attr->a_vals[last];
					attr->a_vals[last].bv_val = NULL;
					bv--;
					break;

				case REWRITE_REGEXEC_ERR:
					/*
					 * FIXME: better give up,
					 * skip the attribute
					 * or leave it untouched?
					 */
					break;
				}
			}
		}
next_attr:;

		*attrp = attr;
		attrp = &attr->a_next;
	}
	rs->sr_entry = &ent;
	rs->sr_attrs = op->oq_search.rs_attrs;
	send_search_entry( op, rs );
	rs->sr_entry = NULL;
	rs->sr_attrs = NULL;
	while ( ent.e_attrs ) {
		attr = ent.e_attrs;
		ent.e_attrs = attr->a_next;
		if ( attr->a_vals != &dummy ) {
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

static int
is_one_level_rdn(
		const char 	*rdn,
		int 		from
)
{
	for ( ; from--; ) {
		if ( DN_SEPARATOR( rdn[ from ] ) ) {
			return 0;
		}
	}

	return 1;
}


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
		Backend		*be,
		Operation 	*op,
		struct metaconn	*lc,
		int 		i,
		LDAPMessage 	*e,
		AttributeName 	*attrs,
		int 		attrsonly
);

static int
is_one_level_rdn(
		const char	*rdn,
		int		from
);

int
meta_back_search(
		Backend		*be,
		Connection	*conn,
		Operation	*op,
		struct berval	*base,
		struct berval	*nbase,
		int		scope,
		int		deref,
		int		slimit,
		int		tlimit,
		Filter		*filter,
		struct berval	*filterstr,
		AttributeName	*attrs,
		int		attrsonly
)
{
	struct metainfo	*li = ( struct metainfo * )be->be_private;
	struct metaconn *lc;
	struct metasingleconn *lsc;
	struct timeval	tv = { 0, 0 };
	LDAPMessage	*res, *e;
	int	count, rc = 0, *msgid, sres = LDAP_NO_SUCH_OBJECT;
	char *match = NULL, *err = NULL;
	char *mbase = NULL, *mmatch = NULL;
	struct berval mfilter;
	BerVarray v2refs = NULL;
		
	int i, last = 0, candidates = 0;
	struct slap_limits_set *limit = NULL;
	int isroot = 0;

	/*
	 * controls are set in ldap_back_dobind()
	 * 
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */
	lc = meta_back_getconn( li, conn, op, META_OP_ALLOW_MULTIPLE, 
			nbase, NULL );
	if ( !lc || !meta_back_dobind( lc, op ) ) {
 		send_ldap_result( conn, op, LDAP_OTHER,
 				NULL, NULL, NULL, NULL );
		return -1;
	}

	/*
	 * Array of message id of each target
	 */
	msgid = ch_calloc( sizeof( int ), li->ntargets );
	if ( msgid == NULL ) {
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, NULL, NULL, NULL );
		return -1;
	}
	
	/* if not root, get appropriate limits */
	if ( be_isroot( be, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, &op->o_ndn, &limit );
	}

	/* if no time limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0
				&& limit->lms_t_soft > -1
				&& tlimit > limit->lms_t_soft ) {
			tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			send_ldap_result( conn, op, LDAP_ADMINLIMIT_EXCEEDED,
					NULL, NULL, NULL, NULL );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}
	
	/* if no size limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0
				&& limit->lms_s_soft > -1
				&& slimit > limit->lms_s_soft ) {
			slimit = limit->lms_s_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			send_ldap_result( conn, op, LDAP_ADMINLIMIT_EXCEEDED,
					NULL, NULL, NULL, NULL );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}

	/*
	 * Inits searches
	 */
	for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
		char 	*realbase = ( char * )base->bv_val;
		int 	realscope = scope;
		ber_len_t suffixlen;
		char	*mapped_filter, **mapped_attrs;

		if ( lsc->candidate != META_CANDIDATE ) {
			msgid[ i ] = -1;
			continue;
		}

		/* should we check return values? */
		if ( deref != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_DEREF,
					( void * )&deref);
		}
		if ( tlimit != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_TIMELIMIT,
					( void * )&tlimit);
		}
		if ( slimit != -1 ) {
			ldap_set_option( lsc->ld, LDAP_OPT_SIZELIMIT,
					( void * )&slimit);
		}

		/*
		 * modifies the base according to the scope, if required
		 */
		suffixlen = li->targets[ i ]->suffix.bv_len;
		if ( suffixlen > nbase->bv_len ) {
			switch ( scope ) {
			case LDAP_SCOPE_SUBTREE:
				/*
				 * make the target suffix the new base
				 * FIXME: this is very forgiving, because
				 * illegal bases may be turned into 
				 * the suffix of the target.
				 */
				if ( dnIsSuffix( &li->targets[ i ]->suffix,
						nbase ) ) {
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
						suffixlen - nbase->bv_len - 1 ) 
			&& dnIsSuffix( &li->targets[ i ]->suffix, nbase ) ) {
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
 					realbase, conn, &mbase ) ) {
		case REWRITE_REGEXEC_OK:
		if ( mbase == NULL ) {
			mbase = realbase;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"[rw] searchBase [%d]: \"%s\" -> \"%s\"\n",
			i, base->bv_val, mbase );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> searchBase [%d]: \"%s\" -> \"%s\"\n",
				i, base->bv_val, mbase );
#endif /* !NEW_LOGGING */
		break;
		
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, "Operation not allowed",
					NULL, NULL );
			rc = -1;
			goto finish;

		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "rewrite error", NULL, NULL );
			rc = -1;
			goto finish;
		}
	
		/*
		 * Rewrite the search filter, if required
		 */
		switch ( rewrite_session( li->targets[ i ]->rwinfo,
					"searchFilter",
					filterstr->bv_val, conn, &mfilter.bv_val ) ) {
		case REWRITE_REGEXEC_OK:
			if ( mfilter.bv_val != NULL && mfilter.bv_val[ 0 ] != '\0') {
				mfilter.bv_len = strlen( mfilter.bv_val );
			} else {
				if ( mfilter.bv_val != NULL ) {
					free( mfilter.bv_val );
				}
				mfilter = *filterstr;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"[rw] searchFilter [%d]: \"%s\" -> \"%s\"\n",
				i, filterstr->bv_val, mfilter.bv_val );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS,
				"rw> searchFilter [%d]: \"%s\" -> \"%s\"\n",
				i, filterstr->bv_val, mfilter.bv_val );
#endif /* !NEW_LOGGING */
			break;
		
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, "Operation not allowed",
					NULL, NULL );
			rc = -1;
			goto finish;

		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "Rewrite error", NULL, NULL );
			rc = -1;
			goto finish;
		}

		/*
		 * Maps attributes in filter
		 */
		mapped_filter = ldap_back_map_filter( &li->targets[ i ]->at_map,
				&li->targets[ i ]->oc_map, &mfilter,
				BACKLDAP_MAP );
		if ( mapped_filter == NULL ) {
			mapped_filter = ( char * )mfilter.bv_val;
		} else {
			if ( mfilter.bv_val != filterstr->bv_val ) {
				free( mfilter.bv_val );
			}
		}
		mfilter.bv_val = NULL;
		mfilter.bv_len = 0;
	
		/*
		 * Maps required attributes
		 */
		mapped_attrs = ldap_back_map_attrs( &li->targets[ i ]->at_map,
				attrs, BACKLDAP_MAP );
		if ( mapped_attrs == NULL && attrs) {
			for ( count=0; attrs[ count ].an_name.bv_val; count++ );
			mapped_attrs = ch_malloc( ( count + 1 ) * sizeof(char *));
			for ( count=0; attrs[ count ].an_name.bv_val; count++ ) {
				mapped_attrs[ count ] = attrs[ count ].an_name.bv_val;
			}
			mapped_attrs[ count ] = NULL;
		}

		/*
		 * Starts the search
		 */
		msgid[ i ] = ldap_search( lsc->ld, mbase, realscope,
				mapped_filter, mapped_attrs, attrsonly ); 
		if ( mapped_attrs ) {
			free( mapped_attrs );
			mapped_attrs = NULL;
		}
		if ( mapped_filter != filterstr->bv_val ) {
			free( mapped_filter );
			mapped_filter = NULL;
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
	for ( count = 0, rc = 0; candidates > 0; ) {
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

			if ( slimit > 0 && count == slimit ) {
				send_search_result( conn, op,
						LDAP_SIZELIMIT_EXCEEDED,
						NULL, NULL, v2refs, NULL, 
						count );
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
				send_search_result( conn, op, LDAP_OTHER,
						NULL, NULL, v2refs, NULL, 
						count );
				
				/* anything else needs be done? */
				goto finish;

			} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
				e = ldap_first_entry( lsc->ld, res );
				if ( meta_send_entry( be, op, lc, i, e, attrs,
						attrsonly ) == LDAP_SUCCESS ) {
					count++;
				}

				/*
				 * If scope is BASE, we need to jump out
				 * as soon as one entry is found; if
				 * the target pool is properly crafted,
				 * this should correspond to the sole
				 * entry that has the base DN
				 */
				if ( scope == LDAP_SCOPE_BASE && count > 0 ) {
					candidates = 0;
					sres = LDAP_SUCCESS;
					break;
				}
				ldap_msgfree( res );
				gotit = 1;

			} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
				char		**references = NULL;
				LDAPControl	**ctrls = NULL;
				BerVarray	refs;
				int		cnt;

				/*
				 * FIXME: should we collect references
				 * and send them alltogether at the end?
				 */

				rc = ldap_parse_reference( lsc->ld, res,
						&references, &ctrls, 1 );

				if ( rc != LDAP_SUCCESS ) {
					continue;
				}

				if ( references == NULL ) {
					continue;
				}

				for ( cnt = 0; references[ cnt ]; cnt++ )
					/* NO OP */ ;
				
				refs = ch_calloc( cnt + 1, sizeof( struct berval ) );

				for ( cnt = 0; references[ cnt ]; cnt++ ) {
					refs[ cnt ].bv_val = references[ cnt ];
					refs[ cnt ].bv_len = strlen( references[ cnt ] );
				}

				/* ignore return value by now */
				( void )send_search_reference( be, conn, op, 
						NULL, refs, ctrls, &v2refs );

				/* cleanup */
				if ( references ) {
					ldap_value_free( references );
					ch_free( refs );
				}

				if ( ctrls ) {
					ldap_controls_free( ctrls );
				}

			} else {
				sres = ldap_result2error( lsc->ld,
						res, 1 );
				sres = ldap_back_map_result( sres );
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
		rc = meta_back_op_result( lc, op );
		goto finish;
	}

	/*
	 * Rewrite the matched portion of the search base, if required
	 * 
	 * FIXME: only the last one gets caught!
	 */
	if ( match != NULL ) {
		switch ( rewrite_session( li->targets[ last ]->rwinfo,
					"matchedDn", match, conn, &mmatch ) ) {
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
	send_search_result( conn, op, sres, mmatch, err, v2refs, NULL, count );

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
		Backend 	*be,
		Operation 	*op,
		struct metaconn *lc,
		int 		target,
		LDAPMessage 	*e,
		AttributeName 	*attrs,
		int 		attrsonly
)
{
	struct metainfo 	*li = ( struct metainfo * )be->be_private;
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
				"searchResult", bdn.bv_val, lc->conn, &ent.e_name.bv_val ) ) {
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
 					" -> \"%s\"\n", target, bdn.bv_val, ent.e_name.bv_val );
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
			int i, last;
			for ( last = 0; attr->a_vals[ last ].bv_val; ++last );
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++, i++ ) {
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
					i--;

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
			int i;
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++, i++ ) {
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
		*attrp = attr;
		attrp = &attr->a_next;
	}
	send_search_entry( be, lc->conn, op, &ent, attrs, attrsonly, NULL );
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


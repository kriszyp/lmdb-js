/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
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

static void
meta_send_entry(
		Backend		*be,
		Operation 	*op,
		struct metaconn	*lc,
		int 		i,
		LDAPMessage 	*e,
		struct berval 		**attrs,
		int 		attrsonly
);

static int
is_one_level_rdn(
		const char *rdn,
		int len
);

int
meta_back_search(
		Backend		*be,
		Connection	*conn,
		Operation	*op,
		const char	*base,
		const char	*nbase,
		int		scope,
		int		deref,
		int		slimit,
		int		tlimit,
		Filter		*filter,
		const char	*filterstr,
		struct berval		**attrs,
		int		attrsonly
)
{
	struct metainfo	*li = ( struct metainfo * )be->be_private;
	struct metaconn *lc;
	struct metasingleconn **lsc;
	struct timeval	tv;
	LDAPMessage	*res, *e;
	int	count, rc = 0, *msgid, sres = LDAP_NO_SUCH_OBJECT;
	char *match = NULL, *err = NULL;
	char *mbase = NULL, *mfilter = NULL, *mmatch = NULL, 
		*mapped_filter = NULL, **mapped_attrs = NULL;
		
	int i, last = 0, candidates = 0, nbaselen, op_type;
	struct slap_limits_set *limit = NULL;
	int isroot = 0;

	if ( scope == LDAP_SCOPE_BASE ) {
		op_type = META_OP_REQUIRE_SINGLE;
	} else {
		op_type = META_OP_ALLOW_MULTIPLE;
	}
	
	lc = meta_back_getconn( li, conn, op, op_type, nbase, NULL );
	if ( !lc || !meta_back_dobind( lc, op ) ) {
		return -1;
	}

	/*
	 * Array of message id of each target
	 */
	msgid = ch_calloc( sizeof( int ), li->ntargets );
	if ( msgid == NULL ) {
		send_search_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, NULL, NULL, NULL, 0 );
		return -1;
	}
	
	nbaselen = strlen( nbase );

	/* if not root, get appropriate limits */
	if ( be_isroot( be, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, op->o_ndn.bv_val, &limit );
	}

	/* if no time limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0 ) {
			tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}
	
	/* if no size limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0 ) {
			slimit = limit->lms_s_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}

	/*
	 * Inits searches
	 */
	for ( i = 0, lsc = lc->conns; lsc[ 0 ] != NULL; ++i, ++lsc ) {
		char *realbase = ( char * )base;
		int realscope = scope;
		int suffixlen;
		
		if ( lsc[ 0 ]->candidate != META_CANDIDATE ) {
			continue;
		}

		if ( deref != -1 ) {
			ldap_set_option( lsc[ 0 ]->ld, LDAP_OPT_DEREF,
					( void * )&deref);
		}
		if ( tlimit != -1 ) {
			ldap_set_option( lsc[ 0 ]->ld, LDAP_OPT_TIMELIMIT,
					( void * )&tlimit);
		}
		if ( slimit != -1 ) {
			ldap_set_option( lsc[ 0 ]->ld, LDAP_OPT_SIZELIMIT,
					( void * )&slimit);
		}

		/*
		 * modifies the base according to the scope, if required
		 */
		suffixlen = strlen( li->targets[ i ]->suffix );
		if ( suffixlen > nbaselen ) {
			switch ( scope ) {
			case LDAP_SCOPE_SUBTREE:
				/*
				 * make the target suffix the new base
				 * FIXME: this is very forgiving, because
				 * illegal bases may be turned into 
				 * the suffix of the target.
				 */
				if ( dn_issuffix( li->targets[ i ]->suffix,
						nbase ) ) {
					realbase = li->targets[ i ]->suffix;
				} else {
					/*
					 * this target is no longer candidate
					 */
					lsc[ 0 ]->candidate = META_NOT_CANDIDATE;
					continue;
				}
				break;

			case LDAP_SCOPE_ONELEVEL:
				if ( is_one_level_rdn( li->targets[ i ]->suffix,
						suffixlen-nbaselen-1) 
			&& dn_issuffix( li->targets[ i ]->suffix, nbase ) ) {
					/*
					 * if there is exactly one level,
					 * make the target suffix the new
					 * base, and make scope "base"
					 */
					realbase = li->targets[ i ]->suffix;
					realscope = LDAP_SCOPE_BASE;
					break;
				} /* else continue with the next case */

			case LDAP_SCOPE_BASE:
				/*
				 * this target is no longer candidate
				 */
				lsc[ 0 ]->candidate = META_NOT_CANDIDATE;
				continue;
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
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] searchBase: \"%s\" -> \"%s\"\n",
				base, mbase ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> searchBase: \"%s\" -> \"%s\"\n%s",
				base, mbase, "" );
#endif /* !NEW_LOGGING */
		break;
		
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, "Unwilling to perform",
					NULL, NULL );
			rc = -1;
			goto finish;

		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
					NULL, "Operations error",
					NULL, NULL );
			rc = -1;
			goto finish;
		}
	
		/*
		 * Rewrite the search filter, if required
		 */
		switch ( rewrite_session( li->targets[ i ]->rwinfo,
					"searchFilter",
					filterstr, conn, &mfilter ) ) {
		case REWRITE_REGEXEC_OK:
			if ( mfilter == NULL || mfilter[ 0 ] == '\0') {
				if ( mfilter != NULL ) {
					free( mfilter );
				}
				mfilter = ( char * )filterstr;
			}
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
					"[rw] searchFilter: \"%s\" -> \"%s\"\n",
					filterstr, mfilter ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS,
				"rw> searchFilter: \"%s\" -> \"%s\"\n%s",
				filterstr, mfilter, "" );
#endif /* !NEW_LOGGING */
			break;
		
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL );
			rc = -1;
			goto finish;

		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
					NULL, NULL, NULL, NULL );
			rc = -1;
			goto finish;
		}

		/*
		 * Maps attributes in filter
		 */
		mapped_filter = ldap_back_map_filter( &li->targets[ i ]->at_map,
				&li->targets[ i ]->oc_map,
				( char * )mfilter, 0 );
		if ( mapped_filter == NULL ) {
			mapped_filter = ( char * )mfilter;
		}
	
		/*
		 * Maps required attributes
		 */
		mapped_attrs = ldap_back_map_attrs( &li->targets[ i ]->at_map,
				attrs, 0 );
		if ( mapped_attrs == NULL ) {
			mapped_attrs = attrs;
		}

		/*
		 * Starts the search
		 */
		msgid[ i ] = ldap_search( lsc[ 0 ]->ld, mbase, realscope,
				mapped_filter, mapped_attrs, attrsonly); 
		if ( msgid[ i ] == -1 ) {
			lsc[ 0 ]->candidate = META_NOT_CANDIDATE;
			continue;
		}

		if ( mapped_attrs != attrs ) {
			charray_free( mapped_attrs );
			mapped_attrs = NULL;
		}
		if ( mapped_filter != mfilter ) {
			free( mapped_filter );
			mapped_filter = NULL;
		}
		if ( mfilter != filterstr ) {
			free( mfilter );
			mfilter = NULL;
		}
		if ( mbase != realbase ) {
			free( mbase );
			mbase = NULL;
		}

		++candidates;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */


	/*
	 * In case there are no candidates, no cycle takes place...
	 */
	for ( count = 0, rc = 0; candidates > 0; ) {
		int ab, gotit = 0;

		/* check for abandon */
		ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
		ab = op->o_abandon;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

		for ( i = 0, lsc = lc->conns; lsc[ 0 ] != NULL; lsc++, i++ ) {
			if ( lsc[ 0 ]->candidate != META_CANDIDATE ) {
				continue;
			}
			
			if ( ab ) {
				ldap_abandon( lsc[ 0 ]->ld, msgid[ i ] );
				rc = 0;
				break;
			}

			if ( slimit > 0 && count == slimit ) {
				send_search_result( conn, op,
						LDAP_SIZELIMIT_EXCEEDED,
						NULL, NULL, NULL, NULL, count );
				goto finish;
			}

			rc = ldap_result( lsc[ 0 ]->ld, msgid[ i ],
					0, &tv, &res );

			if ( rc == 0 ) {
				continue;
			} else if ( rc == -1 ) {
				/* something REALLY bad happened! */
				( void )meta_clear_unused_candidates( li,
						lc, -1, 0 );
				send_search_result( conn, op,
						LDAP_OPERATIONS_ERROR,
						"", "", NULL, NULL, count );
				
				/* anything else needs be done? */
				goto finish;
			} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
				e = ldap_first_entry( lsc[ 0 ]->ld,res );
				meta_send_entry(be, op, lc, i, e, attrs,
						attrsonly);
				count++;
				ldap_msgfree( res );
				gotit = 1;
			} else {
				sres = ldap_result2error( lsc[ 0 ]->ld,
						res, 1 );
				sres = ldap_back_map_result( sres );
				if ( err != NULL ) {
					free( err );
				}
				ldap_get_option( lsc[ 0 ]->ld,
						LDAP_OPT_ERROR_STRING, &err );
				if ( match != NULL ) {
					free( match );
				}
				ldap_get_option( lsc[ 0 ]->ld,
						LDAP_OPT_MATCHED_DN, &match );

#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
						"meta_back_search [%d]"
						" match=\"%s\" err=\"%s\"\n",
						i, match, err ));
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY,
	"=>meta_back_search [%d] match=\"%s\" err=\"%s\"\n",
     					i, match, err );	
#endif /* !NEW_LOGGING */
				
				last = i;
				rc = 0;

				/*
				 * When no candidates are left,
				 * the outer cycle finishes
				 */
				lsc[ 0 ]->candidate = META_NOT_CANDIDATE;
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
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
					"[rw] matchedDn: \"%s\" -> \"%s\"\n",
					match, mmatch ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> matchedDn:"
				       " \"%s\" -> \"%s\"\n%s",
				       match, mmatch, "" );
#endif /* !NEW_LOGGING */
			break;
			
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL );
			rc = -1;
			goto finish;
			
		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
					NULL, NULL, NULL, NULL );
			rc = -1;
			goto finish;
		}
	}

	send_search_result( conn, op, sres,
		mmatch, err, NULL, NULL, count );

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
		free( msgid );
	}
	
	return rc;
}

static void
meta_send_entry(
		Backend *be,
		Operation *op,
		struct metaconn *lc,
		int target,
		LDAPMessage *e,
		struct berval **attrs,
		int attrsonly
)
{
	struct metainfo *li = ( struct metainfo * )be->be_private;
	char *a, *mapped;
	Entry ent;
	BerElement *ber = NULL;
	Attribute *attr, **attrp;
	struct berval *dummy = NULL;
	struct berval *bv;
	const char *text;
	char *dn;

	struct metasingleconn *lsc = lc->conns[ target ];

	dn = ldap_get_dn( lsc->ld, e );
	if ( dn == NULL ) {
		return;
	}

	/*
	 * Rewrite the dn of the result, if needed
	 */
	switch ( rewrite_session( li->targets[ target ]->rwinfo,
				"searchResult", dn, lc->conn, &ent.e_dn ) ) {
	case REWRITE_REGEXEC_OK:
		if ( ent.e_dn == NULL ) {
			ent.e_dn = dn;
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
					"[rw] searchResult[%d]:"
					" \"%s\" -> \"%s\"\n",
					target, dn, ent.e_dn ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> searchResult[%d]: \"%s\""
 					" -> \"%s\"\n", target, dn, ent.e_dn );
#endif /* !NEW_LOGGING */
			free( dn );
			dn = NULL;
		}
		break;
		
	case REWRITE_REGEXEC_ERR:
	case REWRITE_REGEXEC_UNWILLING:
		free( dn );
		return;
	}

	ent.e_ndn = ch_strdup( ent.e_dn );
	( void )dn_normalize( ent.e_ndn );

	/*
	 * cache dn
	 */
	if ( li->cache.ttl != META_DNCACHE_DISABLED ) {
		( void )meta_dncache_update_entry( &li->cache,
						   ch_strdup( ent.e_ndn ),
						   target );
	}

	ent.e_id = 0;
	ent.e_attrs = 0;
	ent.e_private = 0;
	attrp = &ent.e_attrs;

	for ( a = ldap_first_attribute( lsc->ld, e, &ber );
			a != NULL;
			a = ldap_next_attribute( lsc->ld, e, ber ) )
	{
		mapped = ldap_back_map( &li->targets[ target ]->at_map, a, 1 );
		if ( mapped == NULL ) {
			continue;
		}
		attr = ( Attribute * )ch_malloc( sizeof( Attribute ) );
		if ( attr == NULL ) {
			continue;
		}
		attr->a_next = 0;
		attr->a_desc = NULL;
		if ( slap_str2ad( mapped, &attr->a_desc, &text )
				!= LDAP_SUCCESS) {
			if (slap_str2undef_ad(mapped, &attr->a_desc, &text) 
					!= LDAP_SUCCESS) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
						"slap_str2undef_ad(%s): "
						"%s\n", mapped, text ));
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY,
						"slap_str2undef_ad(%s): "
						"%s\n%s", mapped, text, "" );
#endif /* !NEW_LOGGING */
				ch_free(attr);
				continue;
			}
		}
		attr->a_vals = ldap_get_values_len( lsc->ld, e, a );
		if ( !attr->a_vals ) {
			attr->a_vals = &dummy;
		} else if ( strcasecmp( mapped, "objectClass" ) == 0 ) {
			int i, last;
			for ( last = 0; attr->a_vals[ last ]; ++last ) ;
			for ( i = 0; ( bv = attr->a_vals[ i ] ); i++ ) {
				mapped = ldap_back_map(
						&li->targets[ target]->oc_map,
						bv->bv_val, 1 );
				if ( mapped == NULL ) {
					ber_bvfree( attr->a_vals[ i ] );
					attr->a_vals[ i ] = NULL;
					if ( --last < 0 ) {
						break;
					}
					attr->a_vals[ i ] = 
						attr->a_vals[ last ];
					attr->a_vals[ last ] = NULL;
					--i;
				} else if ( mapped != bv->bv_val ) {
					ch_free( bv->bv_val );
					bv->bv_val = ch_strdup( mapped );
					bv->bv_len = strlen( mapped );
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
			for ( i = 0; ( bv = attr->a_vals[ i ] ); i++ ) {
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
					LDAP_LOG(( "backend",
							LDAP_LEVEL_DETAIL1,
							"[rw] searchResult on"
							" attr=%s:"
							" \"%s\" -> \"%s\"\n",
					attr->a_desc->ad_type->sat_cname.bv_val,
							bv->bv_val, newval ));
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
			ber_bvecfree(attr->a_vals);
		}
		free( attr );
	}
	if ( ber ) {
		ber_free( ber, 0 );
	}
	
	if ( ent.e_dn ) {
		free( ent.e_dn );
	}
	if ( ent.e_ndn ) {
		free( ent.e_ndn );
	}
}

static int
is_one_level_rdn(
		const char *rdn,
		int len
)
{
	for ( ; len--; ) {
		if ( LDAP_DNSEPARATOR( rdn[ len ] ) ) {
			return 0;
		}
	}

	return 1;
}


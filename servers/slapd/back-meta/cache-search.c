/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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
 * Masarati and Apurva Kumar.
 */
/* This is an altered version */
/*
 * This software is based on the backends back-ldap and back-meta, implemented
 * by Howard Chu <hyc@highlandsun.com>, Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. 
 *
 * The original copyright statements follow. 
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "ldap_log.h"
#include "../../../libraries/libldap/ldap-int.h"

static Entry* 
meta_create_entry(
	Backend 	*be,
	struct metaconn *lc,
	int 		target,
	LDAPMessage 	*e,
	struct exception* result
); 

static int
is_one_level_rdn(
	const char	*rdn,
	int		from
);

static struct metaconn*  
metaConnect(
	Operation		*op, 
	SlapReply		*rs,
	int			op_type, 
	struct berval		*nbase, 
	struct exception	*result 
);

static void
add_filter_attrs(
	AttributeName** newattrs, 
	AttributeName* attrs, 
	AttributeName* filter_attrs
);

static int 
handleLdapResult(
	struct metaconn* lc, 
	Operation* op, 
	SlapReply *rs,
	int* msgid, Backend* be, 
	AttributeName* attrs, 
	int attrsonly, 
	int candidates, 
	int cacheable, 
	Entry*** entry_array, 
	int curr_limit, 
	int slimit,
	struct exception* result
);

static Entry* 
get_result_entry(
	Backend* be,
	struct metaconn* lc, 
	struct metasingleconn* lsc, 
	int* msgid,
	int i, 
	struct timeval* tv, 
	struct exception* result
); 

static void
rewriteSession(
	struct rewrite_info* info, 
	const char* rewriteContext, 
	const char* string, 
	const void* cookie,  
	char** base, 
	struct exception* result
);

static int 
get_attr_set(
	AttributeName* attrs, 
	query_manager* qm, 
	int num
);

static int 
attrscmp(
	AttributeName* attrs_in, 
	AttributeName* attrs
);

static char* 
cache_entries(
	Operation	*op,
	SlapReply	*rs,
	Entry** entry_array, 
	cache_manager* cm, 
	struct exception* result
); 

static int 
is_temp_answerable(
	int attr_set, 
	struct berval* tempstr, 
	query_manager* qm, 
	int template_id
);

static void*
consistency_check(
	void	*op
); 

static int
cache_back_sentry(
	Operation* op, 
	SlapReply *rs
);


int
meta_back_cache_search(
	Operation	*op,
	SlapReply	*rs )
	/*
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*base,
	struct berval	*nbase,
	int		scope,
	int		deref,
	int		slimit,
	int		tlimit,
	Filter		*filt,
	struct berval	*filterstr,
	AttributeName	*attributes,
	int		attrsonly
) */
{
	struct metainfo		*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn 	*lc;
	struct metasingleconn 	*lsc;
	cache_manager*		cm = li->cm; 
	query_manager*		qm = cm->qm; 

	Operation		*oper;

	time_t			curr_time; 

	int count, rc = 0, *msgid = NULL; 
	char *mbase = NULL;
	char *cbase = NULL; 
	char *uuid; 
	    
	int i = -1, last = 0, candidates = 0, op_type;

	struct berval 	mfilter;
	struct berval	cachebase = { 0L, NULL };  
	struct berval	ncachebase = { 0L, NULL };  
	struct berval	cache_suffix; 
	struct berval 	tempstr = { 0L, NULL }; 

	AttributeName	*filter_attrs = NULL; 
	AttributeName	*new_attrs = NULL; 
	AttributeName	*attrs = NULL; 

	Entry       	*e;
	Entry		**entry_array = NULL;

	Query		query; 

	int 		attr_set = -1; 
	int 		template_id = -1; 
	int 		answerable = 0; 
	int 		cacheable = 0; 
	int 		num_entries = 0;
	int		curr_limit;
	int		fattr_cnt=0; 
	int		oc_attr_absent = 1;

	struct exception result[1]; 

	Filter* filter = str2filter(op->ors_filterstr.bv_val); 
	slap_callback cb = {cache_back_sentry, NULL}; 

	cb.sc_private = op->o_bd; 

	if (op->ors_attrs) {
		for ( count=0; op->ors_attrs[ count ].an_name.bv_val; count++ ) {
			if ( op->ors_attrs[count].an_desc == slap_schema.si_ad_objectClass )
				oc_attr_absent = 0;
		}
		attrs = (AttributeName*)malloc( ( count + 1 + oc_attr_absent )
								*sizeof(AttributeName));
		for ( count=0; op->ors_attrs[ count ].an_name.bv_val; count++ ) {
			ber_dupbv(&attrs[ count ].an_name,
						&op->ors_attrs[ count ].an_name);
			attrs[count].an_desc = op->ors_attrs[count].an_desc; 
		}
		attrs[ count ].an_name.bv_val = NULL;
		attrs[ count ].an_name.bv_len = 0;
	}

	result->type = SUCCESS; 
	result->rc = 0; 
	ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
	cm->threads++; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Threads++ = %d\n", cm->threads, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ANY, "Threads++ = %d\n", cm->threads, 0, 0 );
#endif /* !NEW_LOGGING */
	ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 
	
	ldap_pvt_thread_mutex_lock(&cm->cc_mutex); 
	if (!cm->cc_thread_started) {
		oper = (Operation*)malloc(sizeof(Operation)); 
		*oper = *op; 
		cm->cc_thread_started = 1; 
                ldap_pvt_thread_create(&(cm->cc_thread), 1, consistency_check, (void*)oper); 
	}	
	ldap_pvt_thread_mutex_unlock(&cm->cc_mutex); 

	filter2template(filter, &tempstr, &filter_attrs, &fattr_cnt, result);  
	if (result->type != SUCCESS) 
		goto Catch; 

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "query template of incoming query = %s\n",
					tempstr.bv_val, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ANY, "query template of incoming query = %s\n",
					tempstr.bv_val, 0, 0 );
#endif /* !NEW_LOGGING */
	curr_limit = cm->num_entries_limit ;

	/* find attr set */	
	attr_set = get_attr_set(attrs, qm, cm->numattrsets); 
    
	query.filter = filter; 
	query.attrs = attrs; 
	query.base = op->o_req_dn; 
	query.scope = op->ors_scope; 

	/* check for query containment */
	if (attr_set > -1) {
		for (i=0; i<cm->numtemplates; i++) {
			/* find if template i can potentially answer tempstr */
			if (!is_temp_answerable(attr_set, &tempstr, qm, i)) 
				continue; 
			if (attr_set == qm->templates[i].attr_set_index) {
				cacheable = 1; 
				template_id = i; 
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL2,
					"Entering QC, querystr = %s\n",
			 		op->ors_filterstr.bv_val, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_NONE, "Entering QC, querystr = %s\n",
			 		op->ors_filterstr.bv_val, 0, 0 );
#endif /* !NEW_LOGGING */
			answerable = (*(qm->qcfunc))(qm, &query, i);

			if (answerable)
				break;
		}
	}

	if ( attrs && oc_attr_absent ) {
		for ( count = 0; attrs[count].an_name.bv_val; count++) ;
		attrs[ count ].an_name.bv_val = "objectClass";
		attrs[ count ].an_name.bv_len = strlen( "objectClass" );
		attrs[ count ].an_desc = slap_schema.si_ad_objectClass;
		attrs[ count + 1 ].an_name.bv_val = NULL;
		attrs[ count + 1 ].an_name.bv_len = 0;
	}

	if (answerable) {
		Operation	op_tmp;

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "QUERY ANSWERABLE\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY, "QUERY ANSWERABLE\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		rewriteSession(li->rwinfo, "cacheBase", op->o_req_dn.bv_val,
					op->o_conn, &cbase, result); 
		if (result->type != SUCCESS) { 
			ldap_pvt_thread_rdwr_runlock(&qm->templates[i].t_rwlock); 
			goto Catch; 
		}
		if ( cbase == NULL ) {
			cachebase = op->o_req_dn;
		} else {
			cachebase.bv_val = cbase;
			cachebase.bv_len = strlen(cbase);
		}
		dnNormalize(0, NULL, NULL, &cachebase, &ncachebase,
				op->o_tmpmemctx); 

		/* FIXME: safe default? */
		op_tmp = *op;

		op_tmp.o_bd = li->glue_be;
		op_tmp.o_req_dn = cachebase;
		op_tmp.o_req_ndn = ncachebase;

		op_tmp.o_callback = &cb; 

		li->glue_be->be_search(&op_tmp, rs);
		free( ncachebase.bv_val );
		if ( cachebase.bv_val != op->o_req_dn.bv_val ) {
			/* free only if rewritten */
			free( cachebase.bv_val );
		}

		ldap_pvt_thread_rdwr_runlock(&qm->templates[i].t_rwlock); 
	} else {
		Operation	op_tmp;
		op_tmp = *op;
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "QUERY NOT ANSWERABLE\n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY, "QUERY NOT ANSWERABLE\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */

		if ( op->ors_scope == LDAP_SCOPE_BASE ) {
			op_type = META_OP_REQUIRE_SINGLE;
		} else {
			op_type = META_OP_ALLOW_MULTIPLE;
		}

		lc = metaConnect(&op_tmp, rs, op_type,
				&op->o_req_ndn, result);

		if (result->type != SUCCESS) 
			goto Catch; 

		ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
		if (cm->num_cached_queries >= cm->max_queries) {
			cacheable = 0; 
		}
		ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 
		
		if (cacheable) {
			add_filter_attrs(&new_attrs, attrs, filter_attrs);
		} else {
			new_attrs = attrs; 
		}

		free(filter_attrs); 
	
		/*
		 * Array of message id of each target
		 */
		msgid = ch_calloc( sizeof( int ), li->ntargets );
		if ( msgid == NULL ) {
			result->type = CONN_ERR; 
			goto Catch; 
		}

		/*
		if (slimit > 0 &&  (slimit <= cm->num_entries_limit))  
			slimit = cm->num_entries_limit; 
		*/

		/*
		 * Inits searches
		 */

		for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
			char 	*realbase = ( char * )op->o_req_dn.bv_val;
			int 	realscope = op->ors_scope;
			ber_len_t suffixlen;
			char	*mapped_filter, **mapped_attrs;

			/* FIXME: Check for more than one targets */
			if ( meta_back_is_candidate(
					&li->targets[i]->suffix,
					&op->o_req_ndn ))
				lsc->candidate = META_CANDIDATE; 

			if ( lsc->candidate != META_CANDIDATE ) 
				continue;

			if ( op->ors_deref != -1 ) {
				ldap_set_option( lsc->ld, LDAP_OPT_DEREF,
						( void * )&op->ors_deref);
			}
			if ( op->ors_tlimit != -1 ) {
				ldap_set_option( lsc->ld, LDAP_OPT_TIMELIMIT,
						( void * )&op->ors_tlimit);
			}
			if ( op->ors_slimit != -1 ) {
				ldap_set_option( lsc->ld, LDAP_OPT_SIZELIMIT,
						( void * )&op->ors_slimit);
			}

			/*
			 * modifies the base according to the scope, if required
			 */
			suffixlen = li->targets[ i ]->suffix.bv_len;
			if ( suffixlen > op->o_req_ndn.bv_len ) {
				switch ( op->ors_scope ) {
				case LDAP_SCOPE_SUBTREE:
					/*
					 * make the target suffix the new base
					 * FIXME: this is very forgiving,
					 * because illegal bases may be turned
					 * into the suffix of the target.
					 */
					if ( dnIsSuffix(
						&li->targets[ i ]->suffix,
						&op->o_req_ndn ) ) {
						realbase =
						li->targets[i]->suffix.bv_val;
					} else {
						/*
						 * this target is no longer
						 * candidate
						 */
						lsc->candidate =
							META_NOT_CANDIDATE;
						continue;
					}
					break;

				case LDAP_SCOPE_ONELEVEL:
					if ( is_one_level_rdn(
						li->targets[ i ]->suffix.bv_val,
					       	suffixlen - op->o_req_ndn.bv_len - 1 )
						&& dnIsSuffix(
						&li->targets[ i ]->suffix,
						&op->o_req_ndn ) ) {
						/*
						 * if there is exactly one
						 * level, make the target suffix
						 * the new base, and make scope
						 * "base"
						 */
						realbase =
						li->targets[i]->suffix.bv_val;
						realscope = LDAP_SCOPE_BASE;
						break;
					} /* else continue with the next case */

				case LDAP_SCOPE_BASE:
					/*
					 * this target is no longer candidate
					 */
					lsc->candidate = META_NOT_CANDIDATE;
					continue;
				}
			}

			/*
			 * Rewrite the search base, if required
			 */

			rewriteSession(li->targets[i]->rwmap.rwm_rw,
					"searchBase",
					realbase, op->o_conn, &mbase, result); 

			if (result->type != SUCCESS)
				goto Catch; 

			if ( mbase == NULL ) {
				mbase = realbase;
			}

			/*
			 * Rewrite the search filter, if required
			 */
			rewriteSession( li->targets[i]->rwmap.rwm_rw,
					"searchFilter",
					op->ors_filterstr.bv_val, op->o_conn,
					&mfilter.bv_val, result);
			if (result->type != SUCCESS) 
				goto Catch; 

			if ( mfilter.bv_val != NULL && mfilter.bv_val[ 0 ]
								!= '\0') {
				mfilter.bv_len = strlen( mfilter.bv_val );
			} else {
				if ( mfilter.bv_val != NULL ) {
					free( mfilter.bv_val );
				}
				mfilter = op->ors_filterstr;
			}

#if 0
			/*
			 * Maps attributes in filter
			 */
			mapped_filter = ldap_back_map_filter(
					&li->targets[i]->rwmap.rwm_at,
					&li->targets[i]->rwmap.rwm_oc,
					&mfilter, 0 );
			if ( mapped_filter == NULL ) {
				mapped_filter = ( char * )mfilter.bv_val;
			} else {
				if ( mfilter.bv_val != op->ors_filterstr.bv_val ) {
					free( mfilter.bv_val );
				}
			}
			mfilter.bv_val = NULL;
			mfilter.bv_len = 0;
#else
			mapped_filter = (char *) mfilter.bv_val;
#endif

			/*
			 * Maps required attributes
			 */
			if ( ldap_back_map_attrs(
					&li->targets[ i ]->rwmap.rwm_at,
					new_attrs, 0, &mapped_attrs ) ) {
				goto Catch;
			}

			/*
			 * Starts the search
			 */
			msgid[ i ] = ldap_search( lsc->ld, mbase, realscope,
						mapped_filter, mapped_attrs,
						op->ors_attrsonly );

			if ( msgid[ i ] == -1 ) {
				result->type = CONN_ERR; 
				goto Catch; 
				/*
				lsc->candidate = META_NOT_CANDIDATE;
				continue;
				*/
			}

			if ( mapped_attrs ) {
				free( mapped_attrs );
				mapped_attrs = NULL;
			}

			if ( mapped_filter != op->ors_filterstr.bv_val ) {
				free( mapped_filter );
				mapped_filter = NULL;
			}

			if ( mbase != realbase ) {
				free( mbase );
				mbase = NULL;
			}

			++candidates;
		}

		num_entries = handleLdapResult(lc, &op_tmp, rs, msgid,
				op->o_bd, attrs,
				op->ors_attrsonly, candidates, 
				cacheable, &entry_array,
				curr_limit, op->ors_slimit, result); 

		if (result->type != SUCCESS) 
			goto Catch; 
		if (cacheable && (num_entries <= curr_limit)) {

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"QUERY CACHEABLE\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "QUERY CACHEABLE\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
			op_tmp.o_bd = li->glue_be;
			uuid = cache_entries(&op_tmp, rs, entry_array, cm, result); 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"Added query %s UUID %s ENTRIES %d\n",
					op->ors_filterstr.bv_val,
					uuid, num_entries );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
					"Added query %s UUID %s ENTRIES %d\n",
					op->ors_filterstr.bv_val,
					uuid, num_entries );
#endif /* !NEW_LOGGING */
	    
			if (result->type != SUCCESS) 
				goto Catch; 
			(*(qm->addfunc))(qm, &query, template_id, uuid, result); 
			if (result->type != SUCCESS) 
				goto Catch; 
			filter = 0; 
			attrs = 0; 

			/* FIXME : launch do_syncrepl() threads around here
			 *
			 * entryUUID and entryCSN need also to be requested by :
			 */
			/*
 			msgid[ i ] = ldap_search( lsc->ld, mbase, realscope,
						mapped_filter, mapped_attrs, op->ors_attrsonly );
			*/
			/* Also, mbase, realscope, mapped_filter, mapped_attrs need
			 * be managed as arrays. Each element needs to be retained by this point.
			 */

		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"QUERY NOT CACHEABLE no\n",
					0, 0, 0);
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "QUERY NOT CACHEABLE no\n",
					0, 0, 0);
#endif /* !NEW_LOGGING */
		}
	}

Catch:;
	switch (result->type) {
		case SUCCESS: 
			rc = 0; 
			break;

		case FILTER_ERR: 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"Invalid template error\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "Invalid template error\n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			break; 

		case CONN_ERR: 
			rc = -1; 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Could not connect to a remote server\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Could not connect to a remote server\n",
				0, 0, 0 );
#endif /* !NEW_LOGGING */
			send_ldap_error(op, rs, LDAP_OTHER,
					"Connection error" );
			break;
			
		case RESULT_ERR: 
			rc = -1; 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Error in handling ldap_result\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Error in handling ldap_result\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
			break; 

		case REWRITING_ERR: 
			rc = -1; 
			if (result->rc == REWRITE_REGEXEC_UNWILLING) {
				send_ldap_error( op, rs,
						LDAP_UNWILLING_TO_PERFORM,
						"Unwilling to perform" );
			} else {
				send_ldap_error( op, rs, LDAP_OTHER,
						"Rewrite error" );
			}
			break;

		case MERGE_ERR: 
			rc = -1; 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Error in merging entry \n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Error in merging entry \n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
			break;

		case REMOVE_ERR: 
			rc = -1; 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"Error in removing query \n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "Error in removing query \n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			break;

		default:
			/* assert(0); */
			break;
	}


	if ( msgid ) {
		ch_free( msgid );
	}
	if (entry_array)  {
		for (i=0; (e = entry_array[i]); i++) {
			entry_free(e); 
		}
		free(entry_array);
	}
	if (filter) 
		filter_free(filter);

	if (new_attrs) {
		if (new_attrs != attrs) 
			free(new_attrs); 
	}

	if (attrs)
		free(attrs); 

	if (tempstr.bv_val ) {
		free(tempstr.bv_val);
	}
	ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
	cm->threads--; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Threads-- = %d\n", cm->threads, 0, 0 ); 
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ANY, "Threads-- = %d\n", cm->threads, 0, 0 ); 
#endif /* !NEW_LOGGING */
	ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 
	return rc;
}


static Entry* 
meta_create_entry (
	Backend 		*be,
	struct metaconn		*lc,
	int 			target,
	LDAPMessage	 	*e,
	struct exception*	result
)
{
	struct metainfo 	*li = ( struct metainfo * )be->be_private;
	struct berval		a, mapped;
	Entry* 			ent;
	BerElement 		ber = *e->lm_ber;
	Attribute 		*attr, *soc_attr, **attrp;
	struct berval	dummy = { 0, NULL };
	struct berval	*bv, bdn;
	const char 		*text = NULL;
	char* 			ename = NULL; 
	struct berval	sc = { 0, NULL };
	char			textbuf[SLAP_TEXT_BUFLEN];
	size_t			textlen = sizeof(textbuf);

	if ( ber_scanf( &ber, "{m{", &bdn ) == LBER_ERROR ) {
		result->type = CREATE_ENTRY_ERR;  	
		return NULL; 
	}
	ent = (Entry*)malloc(sizeof(Entry)); 

	/*
	 * Rewrite the dn of the result, if needed
	 */
	rewriteSession( li->targets[ target ]->rwmap.rwm_rw, "searchResult",
			bdn.bv_val, lc->conn, &ent->e_name.bv_val, result );  

	if (result->type != SUCCESS) {
		return NULL; 
	}
	if ( ent->e_name.bv_val == NULL ) {
		ber_dupbv(&(ent->e_name), &bdn);
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"[rw] searchResult[%d]: \"%s\" -> \"%s\"\n",
			target, bdn.bv_val, ent->e_name.bv_val );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> searchResult[%d]: \"%s\""
			" -> \"%s\"\n",
			target, bdn.bv_val, ent->e_name.bv_val );
#endif /* !NEW_LOGGING */
		ent->e_name.bv_len = strlen( ent->e_name.bv_val );
	}
        	
	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 * 
	 * FIXME: should we log anything, or delegate to dnNormalize?
	 */
	dnNormalize( 0, NULL, NULL, &ent->e_name, &ent->e_nname, NULL ); 

	/*
	if ( dnNormalize( 0, NULL, NULL, &ent->e_name, &ent->e_nname )
		!= LDAP_SUCCESS )
	{
		return LDAP_INVALID_DN_SYNTAX;
	}
	*/

	/*
	 * cache dn
	 */
	if ( li->cache.ttl != META_DNCACHE_DISABLED ) {
		meta_dncache_update_entry( &li->cache, &ent->e_nname, target );
	}

	ent->e_id = 0;
	ent->e_attrs = 0;
	ent->e_private = 0;
        ent->e_bv.bv_val = 0; 

	attrp = &ent->e_attrs;

	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		ldap_back_map( &li->targets[ target ]->rwmap.rwm_at, 
				&a, &mapped, 1 );
		if ( mapped.bv_val == NULL ) {
			continue;
		}
		attr = ( Attribute * )ch_malloc( sizeof( Attribute ) );
		if ( attr == NULL ) {
			continue;
		}
		attr->a_flags = 0;
		attr->a_next = 0;
		attr->a_desc = NULL;
		attr->a_nvals = NULL;
		if ( slap_bv2ad( &mapped, &attr->a_desc, &text ) != LDAP_SUCCESS) {
			if ( slap_bv2undef_ad( &mapped, &attr->a_desc, &text ) 
					!= LDAP_SUCCESS) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1,
					"slap_bv2undef_ad(%s): %s\n",
					mapped.bv_val, text, 0 );
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
#if 0
		} else if ( attr->a_desc == slap_schema.si_ad_objectClass ||
				attr->a_desc ==
				slap_schema.si_ad_structuralObjectClass) {
#else
		} else if ( attr->a_desc == slap_schema.si_ad_objectClass ) {
#endif
			int i, last;
			for ( last = 0; attr->a_vals[ last ].bv_val; ++last )
				;
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++,i++ ) {
				ldap_back_map( &li->targets[ target]->rwmap.rwm_oc,
						bv, &mapped, 1 );
				if ( mapped.bv_val == NULL ) {
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

			structural_class( attr->a_vals, &sc, NULL, &text, textbuf, textlen );
			soc_attr = (Attribute*) ch_malloc( sizeof( Attribute ));
			soc_attr->a_desc = slap_schema.si_ad_structuralObjectClass;
			soc_attr->a_vals = (BerVarray) ch_malloc( 2* sizeof( BerValue ));
			ber_dupbv( &soc_attr->a_vals[0], &sc );
			soc_attr->a_vals[1].bv_len = 0;
			soc_attr->a_vals[1].bv_val = NULL;
			soc_attr->a_nvals = (BerVarray) ch_malloc( 2* sizeof( BerValue ));
			ber_dupbv( &soc_attr->a_nvals[0], &sc );
			soc_attr->a_nvals[1].bv_len = 0;
			soc_attr->a_nvals[1].bv_val = NULL;

			*attrp = soc_attr;
			attrp = &soc_attr->a_next;

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
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++,i++ ) {
				char *newval;
				rewriteSession(li->targets[ target ]->rwmap.rwm_rw,
						"searchResult", bv->bv_val,
						lc->conn, &newval, result); 
				if (result->type != SUCCESS) {
					/* FIXME : Handle error */
					result->type = SUCCESS; 
				} else {
					/* left as is */
					if ( newval == NULL ) {
						break;
					}
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"[rw] searchResult on "
						"attr=%s: \"%s\" -> \"%s\"\n",
						attr->a_desc->ad_type->
						sat_cname.bv_val,
						bv->bv_val, newval );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ARGS,
						"rw> searchResult on attr=%s:"
						" \"%s\" -> \"%s\"\n",
						attr->a_desc->ad_type->
						sat_cname.bv_val,
						bv->bv_val, newval );
#endif /* !NEW_LOGGING */
					free( bv->bv_val );
					bv->bv_val = newval;
					bv->bv_len = strlen( newval );
				}
			}
		}
		*attrp = attr;
		attrp = &attr->a_next;
	}

	return ent; 
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

static struct metaconn*  
metaConnect(
	Operation*		op, 
	SlapReply		*rs,
	int			op_type, 
	struct berval		*nbase, 
	struct exception	*result)
{
	struct metaconn		*lc; 

	result->type = SUCCESS; 
	lc = meta_back_getconn( op, rs, op_type, nbase, NULL );
	if (!lc) {
		result->type = CONN_ERR; 
		return 0; 
	}
	return lc; 
}

static void
add_filter_attrs(
	AttributeName** new_attrs, 
	AttributeName* attrs, 
	AttributeName* filter_attrs )
{
	struct berval all_user = { sizeof(LDAP_ALL_USER_ATTRIBUTES) -1,
				   LDAP_ALL_USER_ATTRIBUTES };

	struct berval all_op = { sizeof(LDAP_ALL_OPERATIONAL_ATTRIBUTES) -1,
					LDAP_ALL_OPERATIONAL_ATTRIBUTES}; 

	int alluser = 0; 
	int allop = 0; 
	int i; 
	int count; 

	/* duplicate attrs */
        if (attrs == NULL) {
		count = 1; 
	} else { 
		for (count=0; attrs[count].an_name.bv_val; count++) 
			;
	}
	*new_attrs = (AttributeName*)(malloc((count+1)*sizeof(AttributeName))); 
	if (attrs == NULL) { 
		(*new_attrs)[0].an_name.bv_val = "*"; 
		(*new_attrs)[0].an_name.bv_len = 1; 
		(*new_attrs)[1].an_name.bv_val = NULL;
		(*new_attrs)[1].an_name.bv_len = 0; 
		alluser = 1; 
		allop = 0; 
	} else {  
		for (i=0; i<count; i++) {
			(*new_attrs)[i].an_name = attrs[i].an_name; 
			(*new_attrs)[i].an_desc = attrs[i].an_desc;  
		}
		(*new_attrs)[count].an_name.bv_val = NULL; 
		(*new_attrs)[count].an_name.bv_len = 0; 
		alluser = an_find(*new_attrs, &all_user); 
		allop = an_find(*new_attrs, &all_op); 
	}

	for ( i=0; filter_attrs[i].an_name.bv_val; i++ ) {
		if ( an_find(*new_attrs, &filter_attrs[i].an_name ))
			continue; 
		if ( is_at_operational(filter_attrs[i].an_desc->ad_type) ) {
			if (allop) 
				continue; 
		} else if (alluser) 
			continue; 
		*new_attrs = (AttributeName*)(realloc(*new_attrs,
					(count+2)*sizeof(AttributeName))); 
		(*new_attrs)[count].an_name.bv_val =
				filter_attrs[i].an_name.bv_val; 
		(*new_attrs)[count].an_name.bv_len =
				filter_attrs[i].an_name.bv_len; 
		(*new_attrs)[count].an_desc = filter_attrs[i].an_desc; 
		(*new_attrs)[count+1].an_name.bv_val = NULL; 
		(*new_attrs)[count+1].an_name.bv_len = 0; 
		count++; 
	}
}

static int 
handleLdapResult(
	struct metaconn* lc,
	Operation* op, 
	SlapReply *rs,
	int* msgid, Backend* be, 
	AttributeName* attrs, 
	int attrsonly, 
	int candidates, 
	int cacheable, 
	Entry*** entry_array, 
	int curr_limit, 
	int slimit,
	struct exception* result)
{
	Entry  *entry;
	char *match = NULL, *err = NULL, *cache_ename = NULL;
	int sres; 
	int mres = LDAP_SUCCESS; 
	int num_entries = 0, count, i, rc;     
	struct timeval tv = {0, 0}; 
	struct metasingleconn* lsc; 
	struct metainfo 	*li = ( struct metainfo * )be->be_private;
	result->rc = 0; 
	result->type = SUCCESS; 

	for ( count = 0, rc = 0; candidates > 0; ) {
		int ab, gotit = 0;

		/* check for abandon */
		ab = op->o_abandon;

		for ( i = 0, lsc = lc->conns; !META_LAST(lsc); lsc++, i++ ) {
			if ( lsc->candidate != META_CANDIDATE ) {
				continue;
			}

			if ( ab ) {
				ldap_abandon( lsc->ld, msgid[ i ] );
				result->type = ABANDON_ERR;
				break; 
			}

			if ( slimit > 0 && num_entries == slimit ) {
				result->type = SLIMIT_ERR; 
				break; 
			}

			if ((entry = get_result_entry(be, lc, lsc,
						msgid, i, &tv, result))) {
				rs->sr_entry = entry;
				rs->sr_attrs = op->ors_attrs; 
				send_search_entry( op, rs );
				rs->sr_entry = NULL;
				rs->sr_attrs = NULL; 
				if ((cacheable) &&
						(num_entries < curr_limit))  {
					rewriteSession( li->rwinfo,
							"cacheResult",
							entry->e_name.bv_val,
							lc->conn,
							&cache_ename, result );  
					free(entry->e_name.bv_val); 
					if (result->type != SUCCESS) {
						return 0; 
					}
					ber_str2bv(cache_ename,
						strlen(cache_ename),
						0, &entry->e_name); 
					ber_dupbv(&entry->e_nname,
						&entry->e_name); 
					*entry_array = (Entry**)realloc(
							*entry_array,
							(( num_entries+2 ) *
							 sizeof( Entry* )));
					(*entry_array)[num_entries] = entry;	
					(*entry_array)[num_entries+1] = NULL;
				}
				num_entries++; 
				gotit = 1; 
			} else if (result->type == REWRITING_ERR) {
				return 0; 
			} else if (result->type == TIMEOUT_ERR) {
				result->type = SUCCESS; 
				continue;  
			} else if (result->type == CREATE_ENTRY_ERR) {
				break; 
			} else if (result->rc == -1) {
				break; 
			} else {
				rs->sr_err = result->rc;
				sres = ldap_back_map_result(rs);
				if (mres == LDAP_SUCCESS &&
						sres != LDAP_SUCCESS) {
					mres = sres; 
					ldap_get_option(lsc->ld,
						LDAP_OPT_ERROR_STRING, &err);
					ldap_get_option(lsc->ld,
						LDAP_OPT_MATCHED_DN, &match);
				}
				lsc->candidate = META_NOT_CANDIDATE; 
				candidates--; 
				result->type = SUCCESS; 
			}
		}
		switch (result->type) {
		case RESULT_ERR: 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"ldap_result error, rc = -1\n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "ldap_result error, rc = -1\n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			rs->sr_err = LDAP_OTHER;
			send_ldap_result( op, rs );
			return 0; 

		case CREATE_ENTRY_ERR: 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"Error in parsing result \n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "Error in parsing result \n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			rs->sr_err = LDAP_OTHER;
			send_ldap_result( op, rs );
			result->type = RESULT_ERR; 
			return 0; 

		case SLIMIT_ERR: 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1, "Size limit exceeded \n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "Size limit exceeded \n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
			send_ldap_result( op, rs );
			result->type = RESULT_ERR; 
			return 0;

		case ABANDON_ERR: 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"search operation abandoned \n",
					0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY, "search operation abandoned \n",
					0, 0, 0 );
#endif /* !NEW_LOGGING */
			result->type = RESULT_ERR; 
			return 0; 

		default:
			/* assert( 0 ); */
			break;
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

	rs->sr_err = mres;
	rs->sr_text = err;
	rs->sr_matched = match;

	send_ldap_result( op, rs );

	rs->sr_text = NULL;
	rs->sr_matched = NULL;

	if (err) 
		free(err); 

	if (match) 
		free(match); 
    
	result->type = (mres == LDAP_SUCCESS) ? SUCCESS : RESULT_ERR; 
	return num_entries; 
}

static Entry* 
get_result_entry(
	Backend* be, 
	struct metaconn* lc, 
	struct metasingleconn* lsc, 
	int* msgid,
	int i, 
	struct timeval* tv, 
	struct exception* result)
{
	Entry* entry; 
	LDAPMessage	*res, *e; 
	int rc; 
	int sres = LDAP_SUCCESS; 

	rc = ldap_result( lsc->ld, msgid[ i ],
			0, tv, &res );

	if ( rc == 0 ) {
		result->type = TIMEOUT_ERR; 
		return NULL; 
	} else if ( rc == -1 ) {
		result->rc = -1; 
		result->type = RESULT_ERR; 
		return NULL; 
	} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
		e = ldap_first_entry( lsc->ld, res );
		entry = meta_create_entry(be, lc, i, e, result);  
		if (!entry) {
			return NULL; 
		}    
		ldap_msgfree( res );
		result->type = SUCCESS; 
		return entry; 
	} else {
		sres = ldap_result2error( lsc->ld,
				res, 1 );
		result->rc = sres; 
		result->type = RESULT_ERR; 
		return NULL; 
	}
}	

static void
rewriteSession(
	struct rewrite_info* info, 
	const char* rewriteContext, 
	const char* string, 
	const void* cookie,  
	char** base, 
	struct exception* result)
{
	int rc = rewrite_session(info, rewriteContext, string, cookie, base); 
	if (rc != REWRITE_REGEXEC_OK) {
		result->rc = rc; 
		result->type = REWRITING_ERR; 

		if (strcmp(rewriteContext, "searchBase") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting search base\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting search base\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (strcmp(rewriteContext, "searchFilter") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting search filter\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting search filter\n",
				0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (strcmp(rewriteContext, "searchResult") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting DN, or DN syntax "
				"attributes of search result\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting DN, or DN syntax "
				"attributes of search result\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (strcmp(rewriteContext, "cacheBase") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting search base with "
				"cache base\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting search base with "
				"cache base\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (strcmp(rewriteContext, "cacheResult") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting DN for cached entries\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting DN for cached entries\n",
				0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (strcmp(rewriteContext, "cacheReturn") == 0) 
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
				"Problem in rewriting DN for answerable "
				"entries\n", 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
				"Problem in rewriting DN for answerable "
				"entries\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
	} else {
		result->type = SUCCESS;
	}
}

static int 
get_attr_set(
	AttributeName* attrs, 
	query_manager* qm, 
	int num )
{
	int i; 
	for (i=0; i<num; i++) {
		if (attrscmp(attrs, qm->attr_sets[i].attrs)) 
			return i;
	}
	return -1; 
}

static int 
attrscmp(
	AttributeName* attrs_in, 
	AttributeName* attrs)
{
	int i, count1, count2; 
	if ( attrs_in == NULL ) {
		return (attrs ? 0 : 1); 
	} 
	if ( attrs == NULL ) 
		return 0; 
	
	for ( count1=0;
	      attrs_in && attrs_in[count1].an_name.bv_val != NULL;
	      count1++ )
		;
	for ( count2=0;
	      attrs && attrs[count2].an_name.bv_val != NULL;
	      count2++) 
		;
	if ( count1 != count2 )
		return 0; 

	for ( i=0; i<count1; i++ ) {
		if ( !an_find(attrs, &attrs_in[i].an_name ))
			return 0; 
	}
	return 1; 
}

static char* 
cache_entries(
	Operation	*op,
	SlapReply	*rs,
	Entry** entry_array, 
	cache_manager* cm, 
	struct exception* result)
{
	int		i; 
	int		return_val; 
	int		cache_size; 
	Entry		*e; 
	struct berval	query_uuid; 
	struct berval	crp_uuid; 
	char		uuidbuf[ LDAP_LUTIL_UUIDSTR_BUFSIZE ], *crpid; 
	char		crpuuid[40]; 
	query_manager	*qm = cm->qm;
    
	result->type = SUCCESS; 
	query_uuid.bv_len = lutil_uuidstr(uuidbuf, sizeof(uuidbuf)); 
	query_uuid.bv_val = ch_strdup(uuidbuf);

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "UUID for query being added = %s\n",
			uuidbuf, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ANY, "UUID for query being added = %s\n",
			uuidbuf, 0, 0 );
#endif /* !NEW_LOGGING */
	
	for ( i=0; ( entry_array && (e=entry_array[i]) ); i++ ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL2, "LOCKING REMOVE MUTEX\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_NONE, "LOCKING REMOVE MUTEX\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		ldap_pvt_thread_mutex_lock(&cm->remove_mutex); 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL2, "LOCKED REMOVE MUTEX\n", 0, 0, 0);
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_NONE, "LOCKED REMOVE MUTEX\n", 0, 0, 0);
#endif /* !NEW_LOGGING */
		if ( cm->cache_size > (cm->thresh_hi) ) {
			while(cm->cache_size > (cm->thresh_lo)) {
				crpid = cache_replacement(qm);
				if (crpid == NULL) {
					result->type = REMOVE_ERR; 
				} else {
					strcpy(crpuuid, crpid); 
					crp_uuid.bv_val = crpuuid; 
					crp_uuid.bv_len = strlen(crpuuid); 
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"Removing query UUID %s\n",
						crpuuid, 0, 0 );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ANY,
						"Removing query UUID %s\n",
						crpuuid, 0, 0 );
#endif /* !NEW_LOGGING */
					return_val = remove_query_data(op, rs,
							&crp_uuid, result); 
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"QUERY REMOVED, SIZE=%d\n",
						return_val, 0, 0);
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ANY,
						"QUERY REMOVED, SIZE=%d\n",
						return_val, 0, 0);
#endif /* !NEW_LOGGING */
					ldap_pvt_thread_mutex_lock(
							&cm->cache_mutex ); 
					cm->total_entries -= result->rc; 
					cm->num_cached_queries--; 
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"STORED QUERIES = %lu\n",
						cm->num_cached_queries, 0, 0 );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ANY,
						"STORED QUERIES = %lu\n",
						cm->num_cached_queries, 0, 0 );
#endif /* !NEW_LOGGING */
					ldap_pvt_thread_mutex_unlock(
							&cm->cache_mutex );
 					cm->cache_size = (return_val >
						cm->cache_size) ?
					       	0 : (cm->cache_size-return_val);
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_META, DETAIL1,
						"QUERY REMOVED, CACHE SIZE="
						"%lu bytes %d entries\n",
						cm->cache_size,
						cm->total_entries, 0 );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ANY,
						"QUERY REMOVED, CACHE SIZE="
						"%lu bytes %d entries\n",
						cm->cache_size,
						cm->total_entries, 0 );
#endif /* !NEW_LOGGING */
				}
			}
		}

		rs->sr_entry = e;
		return_val = merge_entry(op, rs, &query_uuid, result);
		rs->sr_entry = NULL;
		cm->cache_size += return_val;
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"ENTRY ADDED/MERGED, CACHE SIZE=%lu bytes\n",
			cm->cache_size, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY,
			"ENTRY ADDED/MERGED, CACHE SIZE=%lu bytes\n",
			cm->cache_size, 0, 0 );
#endif /* !NEW_LOGGING */
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL2, "UNLOCKING REMOVE MUTEX\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_NONE, "UNLOCKING REMOVE MUTEX\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		ldap_pvt_thread_mutex_unlock(&cm->remove_mutex); 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL2, "UNLOCKED REMOVE MUTEX\n",
				0, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_NONE, "UNLOCKED REMOVE MUTEX\n", 0, 0, 0 );
#endif /* !NEW_LOGGING */
		if (result->type != SUCCESS) 
			return 0; 
		ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
		cm->total_entries += result->rc; 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"ENTRY ADDED/MERGED, SIZE=%d, CACHED ENTRIES=%d\n",
			return_val, cm->total_entries, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY,
			"ENTRY ADDED/MERGED, SIZE=%d, CACHED ENTRIES=%d\n",
			return_val, cm->total_entries, 0 );
#endif /* !NEW_LOGGING */
		ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 
	}
	ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
	cm->num_cached_queries++; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "STORED QUERIES = %lu\n",
			cm->num_cached_queries, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ANY, "STORED QUERIES = %lu\n",
			cm->num_cached_queries, 0, 0 );
#endif /* !NEW_LOGGING */
	ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 

	return query_uuid.bv_val; 
}

static int 
is_temp_answerable(
	int attr_set, 
	struct berval* tempstr, 
	query_manager* qm, 
	int template_id )
{
	int i; 
	int* id_array; 
	char* str;
	int result = 0; 
	i = qm->templates[template_id].attr_set_index; 
	str = qm->templates[template_id].querystr; 

	if (attr_set == i) {
		result = 1; 
	} else { 
		id_array = qm->attr_sets[attr_set].ID_array;    

		while (*id_array != -1) {
			if (*id_array == i) 
				result = 1; 
			id_array++; 
		}
	}
	if (!result) 
		return 0; 
	if (strcasecmp(str, tempstr->bv_val) == 0)  
		return 1; 
	return 0; 
}

static void* 
consistency_check(void* operation)
{
	Operation* op = (Operation*)operation; 

	SlapReply rs = {REP_RESULT}; 

	struct metainfo *li = ( struct metainfo * )op->o_bd->be_private;
	cache_manager* 	cm = li->cm; 
	query_manager* qm = cm->qm; 
	CachedQuery* query, *query_prev; 
	time_t curr_time; 
	struct berval uuid;  
	struct exception result; 
	int i, return_val; 
	QueryTemplate* templ;


	op->o_bd = li->glue_be;
      
        for(;;) {
	        ldap_pvt_thread_sleep(cm->cc_period);     
		for (i=0; qm->templates[i].querystr; i++) {
			templ = qm->templates + i; 
			query = templ->query_last; 
			curr_time = slap_get_time(); 
			ldap_pvt_thread_mutex_lock(&cm->remove_mutex); 
			while (query && (query->expiry_time < curr_time)) {
				ldap_pvt_thread_mutex_lock(&qm->lru_mutex); 
				remove_query(qm, query); 
				ldap_pvt_thread_mutex_unlock(&qm->lru_mutex); 
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1, "Lock CR index = %d\n",
						i, 0, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, "Lock CR index = %d\n",
						i, 0, 0 );
#endif /* !NEW_LOGGING */
				ldap_pvt_thread_rdwr_wlock(&templ->t_rwlock);  
				remove_from_template(query, templ); 
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1,
						"TEMPLATE %d QUERIES-- %d\n",
						i, templ->no_of_queries, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, "TEMPLATE %d QUERIES-- %d\n",
						i, templ->no_of_queries, 0 );
#endif /* !NEW_LOGGING */
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1, "Unlock CR index = %d\n",
						i, 0, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, "Unlock CR index = %d\n",
						i, 0, 0 );
#endif /* !NEW_LOGGING */
				ldap_pvt_thread_rdwr_wunlock(&templ->t_rwlock);  
				uuid.bv_val = query->q_uuid; 
				uuid.bv_len = strlen(query->q_uuid); 
				return_val = remove_query_data(op, &rs, &uuid, &result); 
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1,
						"STALE QUERY REMOVED, SIZE=%d\n",
						return_val, 0, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, "STALE QUERY REMOVED, SIZE=%d\n",
							return_val, 0, 0 );
#endif /* !NEW_LOGGING */
				ldap_pvt_thread_mutex_lock(&cm->cache_mutex); 
				cm->total_entries -= result.rc; 
				cm->num_cached_queries--; 
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1, "STORED QUERIES = %lu\n",
						cm->num_cached_queries, 0, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, "STORED QUERIES = %lu\n",
						cm->num_cached_queries, 0, 0 );
#endif /* !NEW_LOGGING */
				ldap_pvt_thread_mutex_unlock(&cm->cache_mutex); 
				cm->cache_size = (return_val > cm->cache_size) ?
							0: (cm->cache_size-return_val);
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1,
					"STALE QUERY REMOVED, CACHE SIZE=%lu bytes %d "
					"entries\n", cm->cache_size,
					cm->total_entries, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY,
					"STALE QUERY REMOVED, CACHE SIZE=%lu bytes %d "
					"entries\n", cm->cache_size,
					cm->total_entries, 0 );
#endif /* !NEW_LOGGING */
				query_prev = query; 
				query = query->prev; 
				free_query(query_prev); 
			}
			ldap_pvt_thread_mutex_unlock(&cm->remove_mutex); 
		}
	}
}

static int
cache_back_sentry(
	Operation* op, 
	SlapReply *rs )
{ 
	slap_callback		*cb = op->o_callback; 
	/*struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;*/
	Backend* be = (Backend*)(cb->sc_private);
	struct metainfo		*li = ( struct metainfo * )be->be_private;
 
	char			*ename = NULL;
	struct exception	result;
	struct berval		dn;
	struct berval		ndn;
 
	if (rs->sr_type == REP_SEARCH) {
		dn = rs->sr_entry->e_name; 
		ndn = rs->sr_entry->e_nname; 

		rewriteSession( li->rwinfo, "cacheReturn",
				rs->sr_entry->e_name.bv_val, op->o_conn,
				&ename, &result );  
		ber_str2bv(ename, strlen(ename), 0, &rs->sr_entry->e_name); 
		/* FIXME: should we normalize this? */
		ber_dupbv(&rs->sr_entry->e_nname, &rs->sr_entry->e_name); 

		op->o_callback = NULL; 

		send_search_entry( op, rs );
	 
		rs->sr_entry->e_name = dn; 
		rs->sr_entry->e_nname = ndn; 

		op->o_callback = cb; 
		return 0; 

	} else if (rs->sr_type == REP_RESULT) { 
		op->o_callback = NULL; 
		send_ldap_result( op, rs ); 
		return 0; 
	}

	/* FIXME: not handled? */
	assert(0);
	return -1;
}

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
 * This work was initially developed by the Apurva Kumar for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

static void 	add_query_on_top (query_manager*, CachedQuery*);
static int 	base_scope_compare(struct berval* dn_stored, 
		           	   struct berval* dn_incoming, int scope_stored,
			    	   int scope_incoming);

/* check whether query is contained in any of 
 * the cached queries in template template_index 
 */
int 
query_containment(query_manager* qm, 
		  Query* query, 
		  int template_index)
{
	QueryTemplate* templa= qm->templates;
	CachedQuery* qc;
	Query* q;
	Query* prev_q;
	Filter* inputf = query->filter; 
	struct berval* base = &(query->base); 
	int scope = query->scope; 
	int i,res=0;
	Filter* fs;
	Filter* fi;
	int ret, rc; 
	const char* text; 

	MatchingRule* mrule = NULL;
	if (inputf != NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "Lock QC index = %d\n",
				template_index, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "Lock QC index = %d\n",
				template_index, 0, 0 );
#endif
		ldap_pvt_thread_rdwr_rlock(&(templa[template_index].t_rwlock));  
		for(qc=templa[template_index].query; qc != NULL; qc= qc->next) {
			q = (Query*)qc; 
			if(base_scope_compare(&(q->base), base, q->scope, scope)) {
				fi = inputf;
				fs = q->filter;		 
				do {	
					res=0;
					switch (fs->f_choice) {
					case LDAP_FILTER_EQUALITY:
						if (fi->f_choice == LDAP_FILTER_EQUALITY) 
							mrule = fs->f_ava->aa_desc->ad_type->sat_equality; 
						else 
							ret = 1; 
						break; 
					case LDAP_FILTER_GE:
					case LDAP_FILTER_LE:
						mrule = fs->f_ava->aa_desc->ad_type->sat_ordering; 
						break; 
					default: 
						mrule = NULL; 	
					}
					if (mrule) { 
						rc = value_match(&ret, fs->f_ava->aa_desc, mrule, 
						 	SLAP_MR_VALUE_OF_ASSERTION_SYNTAX, 
							&(fi->f_ava->aa_value), 
							&(fs->f_ava->aa_value), &text); 
						if (rc != LDAP_SUCCESS) {
#ifdef NEW_LOGGING
							LDAP_LOG( BACK_META, DETAIL1,
							"Unlock: Exiting QC index=%d\n",
							template_index, 0, 0 );
#else
							Debug( LDAP_DEBUG_ANY,
							"Unlock: Exiting QC index=%d\n",
							template_index, 0, 0 );
#endif
							ldap_pvt_thread_rdwr_runlock(&(templa[template_index].t_rwlock));  
#ifdef NEW_LOGGING
							LDAP_LOG( BACK_META, DETAIL1,
							"query_containment: Required "
							"matching rule not defined for "
							"a filter attribute",
							0, 0, 0 );  
#else
							Debug( LDAP_DEBUG_ANY,
							"query_containment: Required "
							"matching rule not defined for "
							"a filter attribute",
							0, 0, 0 );  
#endif
							return 0; 
						}
					} 
					switch (fs->f_choice) {
					case LDAP_FILTER_OR: 
					case LDAP_FILTER_AND:
						fs = fs->f_and;
						fi = fi->f_and;
						res=1;
						break; 
					case LDAP_FILTER_SUBSTRINGS: 
						/* check if the equality query can be 
						* answered with cached substring query */
						if ((fi->f_choice == LDAP_FILTER_EQUALITY)
							&& substr_containment_equality(
							fs, fi))
							res=1;		
						/* check if the substring query can be 
						* answered with cached substring query */
						if ((fi->f_choice ==LDAP_FILTER_SUBSTRINGS
							) && substr_containment_substr(
							fs, fi))
							res= 1;
						fs=fs->f_next;
						fi=fi->f_next;	
						break; 
					case LDAP_FILTER_PRESENT: 
						res=1;
						fs=fs->f_next;
						fi=fi->f_next;	
						break; 
					case LDAP_FILTER_EQUALITY: 
						if (ret == 0) 
							res = 1;
						fs=fs->f_next;
						fi=fi->f_next;	
						break; 
					case LDAP_FILTER_GE: 
						if (ret >= 0)
							res = 1; 
						fs=fs->f_next;
						fi=fi->f_next;	
						break;
					case LDAP_FILTER_LE: 
						if (ret <= 0)
							res = 1; 
						fs=fs->f_next;
						fi=fi->f_next;	
						break;
					case LDAP_FILTER_NOT:
						res=0;
						break;
					default:
						break;
					} 
				} while((res) && (fi != NULL) && (fs != NULL));

				if(res) {
					ldap_pvt_thread_mutex_lock(&qm->lru_mutex); 
					if (qm->lru_top != qc) {
						remove_query(qm, qc); 
						add_query_on_top(qm, qc); 
					}
					ldap_pvt_thread_mutex_unlock(&qm->lru_mutex); 
					return 1;
				}	
			}
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
			"Not answerable: Unlock QC index=%d\n",
			template_index, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"Not answerable: Unlock QC index=%d\n",
			template_index, 0, 0 );
#endif
		ldap_pvt_thread_rdwr_runlock(&(templa[template_index].t_rwlock));  
	}
	return 0; 
}

/* remove_query from LRU list */

void 
remove_query (query_manager* qm, CachedQuery* qc) 
{
	CachedQuery* up; 
	CachedQuery* down; 

	if (!qc) 
		return; 

	up = qc->lru_up; 
	down = qc->lru_down; 

	if (!up) 
		qm->lru_top = down; 

	if (!down) 
		qm->lru_bottom = up; 

	if (down) 
		down->lru_up = up; 

	if (up) 
		up->lru_down = down; 

	qc->lru_up = qc->lru_down = NULL; 
}

/* add query on top of LRU list */
void 
add_query_on_top (query_manager* qm, CachedQuery* qc) 
{
	CachedQuery* top = qm->lru_top; 
	Query* q = (Query*)qc; 
    
	qm->lru_top = qc; 

	if (top) 
		top->lru_up = qc; 
	else
		qm->lru_bottom = qc; 
       
	qc->lru_down = top; 
	qc->lru_up = NULL; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Base of added query = %s\n",
			q->base.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Base of added query = %s\n",
			q->base.bv_val, 0, 0 );
#endif
}

void 
free_query (CachedQuery* qc) 
{
	Query* q = (Query*)qc; 
	free(qc->q_uuid); 
	filter_free(q->filter); 
	free (q->base.bv_val); 

	free(q->attrs); 
	free(qc); 
}

/* compare base and scope of incoming and cached queries */
int base_scope_compare(
	struct berval* dn_stored, 
	struct berval* dn_incoming, 
	int scope_stored, 
	int scope_incoming	)
{
	struct berval ndn_incoming = { 0L, NULL }; 
	struct berval pdn_incoming = { 0L, NULL };
	struct berval ndn_stored = { 0L, NULL };

	int i;

	if (scope_stored < scope_incoming)
		return 0;

	dnNormalize(0, NULL, NULL, dn_incoming, &ndn_incoming, NULL);
	dnNormalize(0, NULL, NULL, dn_stored, &ndn_stored, NULL);
	
	i = dnIsSuffix(&ndn_incoming, &ndn_stored);
	
	if ( i == 0 )
		return 0;
	
	switch(scope_stored) {
	case LDAP_SCOPE_BASE:
		if (strlen(ndn_incoming.bv_val) == strlen(ndn_stored.bv_val))
			return 1;
		else	
			return 0;
		break;
	case LDAP_SCOPE_ONELEVEL:
		switch(scope_incoming){
		case LDAP_SCOPE_BASE:
			dnParent(&ndn_incoming, &pdn_incoming); 
			if(strcmp(pdn_incoming.bv_val, ndn_stored.bv_val) == 0)
				return 1;
			else
				return 0;
			break;
		case LDAP_SCOPE_ONELEVEL:
			if (ndn_incoming.bv_len == ndn_stored.bv_len)
				return 1;
			else
				return 0;
			break;
		default:
			return 0;
			break;
		}
	case LDAP_SCOPE_SUBTREE:
		return 1;
		break;
	default:
		return 0;
		break;	
    }
}

/* Add query to query cache */
void add_query(
	query_manager* qm, 
	Query* query, 
	int template_index, 
	char* uuid, 
	struct exception* result)
{
	CachedQuery* new_cached_query = (CachedQuery*) malloc(sizeof(CachedQuery));
	QueryTemplate* templ = (qm->templates)+template_index;  
	Query* new_query;
	new_cached_query->template_id = template_index; 
	new_cached_query->q_uuid = uuid; 
	new_cached_query->lru_up = NULL; 
	new_cached_query->lru_down = NULL; 
	new_cached_query->expiry_time = slap_get_time() + templ->ttl; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Added query expires at %ld\n",
			(long) new_cached_query->expiry_time, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Added query expires at %ld\n",
			(long) new_cached_query->expiry_time, 0, 0 );
#endif
	new_query = (Query*)new_cached_query; 

	new_query->base.bv_val = ch_strdup(query->base.bv_val); 
	new_query->base.bv_len = query->base.bv_len; 
	new_query->scope = query->scope; 
	new_query->filter = query->filter;
	new_query->attrs = query->attrs; 

	/* Adding a query    */
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Lock AQ index = %d\n",
			template_index, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Lock AQ index = %d\n",
			template_index, 0, 0 );
#endif
	ldap_pvt_thread_rdwr_wlock(&templ->t_rwlock);  
	if (templ->query == NULL) 
		templ->query_last = new_cached_query; 
	else 
		templ->query->prev = new_cached_query; 
	new_cached_query->next = templ->query; 
	new_cached_query->prev = NULL; 
	templ->query = new_cached_query; 
	templ->no_of_queries++; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "TEMPLATE %d QUERIES++ %d\n",
			template_index, templ->no_of_queries, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "TEMPLATE %d QUERIES++ %d\n",
			template_index, templ->no_of_queries, 0 );
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Unlock AQ index = %d \n",
			template_index, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Unlock AQ index = %d \n",
			template_index, 0, 0 );
#endif
	ldap_pvt_thread_rdwr_wunlock(&templ->t_rwlock);  

	/* Adding on top of LRU list  */
	ldap_pvt_thread_mutex_lock(&qm->lru_mutex); 
	add_query_on_top(qm, new_cached_query);  
	ldap_pvt_thread_mutex_unlock(&qm->lru_mutex); 

}	

/* remove bottom query of LRU list from the query cache */	
char* cache_replacement(query_manager* qm)
{
	char* result = (char*)(malloc(40));
	CachedQuery* bottom; 
	QueryTemplate* templ; 
	CachedQuery* query_curr; 
	int temp_id;

	ldap_pvt_thread_mutex_lock(&qm->lru_mutex); 
	bottom = qm->lru_bottom; 

	if (!bottom) {
#ifdef NEW_LOGGING
		LDAP_LOG ( BACK_META, DETAIL1,
			"Cache replacement invoked without "
			"any query in LRU list\n", 0, 0, 0 );
#else
		Debug ( LDAP_DEBUG_ANY,
			"Cache replacement invoked without "
			"any query in LRU list\n", 0, 0, 0 );
#endif
		return 0; 
	}

	temp_id = bottom->template_id;
	remove_query(qm, bottom); 
	ldap_pvt_thread_mutex_unlock(&qm->lru_mutex); 

	strcpy(result, bottom->q_uuid); 

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Lock CR index = %d\n", temp_id, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Lock CR index = %d\n", temp_id, 0, 0 );
#endif
	ldap_pvt_thread_rdwr_wlock(&(qm->templates[temp_id].t_rwlock));  
	remove_from_template(bottom, (qm->templates+temp_id)); 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "TEMPLATE %d QUERIES-- %d\n",
		temp_id, qm->templates[temp_id].no_of_queries, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "TEMPLATE %d QUERIES-- %d\n",
		temp_id, qm->templates[temp_id].no_of_queries, 0 );
#endif
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1, "Unlock CR index = %d\n", temp_id, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "Unlock CR index = %d\n", temp_id, 0, 0 );
#endif
	ldap_pvt_thread_rdwr_wunlock(&(qm->templates[temp_id].t_rwlock));  
	free_query(bottom); 
	return result; 
}

void
remove_from_template (CachedQuery* qc, QueryTemplate* template)
{
	if (!qc->prev && !qc->next) {
		template->query_last = template->query = NULL; 
	} else if (qc->prev == NULL) {
		qc->next->prev = NULL; 
		template->query = qc->next; 
	} else if (qc->next == NULL) {
		qc->prev->next = NULL; 
		template->query_last = qc->prev; 
	} else {
		qc->next->prev = qc->prev; 
		qc->prev->next = qc->next; 
	}

	template->no_of_queries--;  
}    

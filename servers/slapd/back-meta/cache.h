/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */


#ifndef META_CACHE_H
#define META_CACHE_H
#include "slap.h"

/* cache specific errors */
enum type_of_result 
{ 
    SUCCESS, 
    CONN_ERR, 
    RESULT_ERR, 
    FILTER_ERR, 
    REWRITING_ERR,
    MERGE_ERR, 
    REMOVE_ERR, 
    SLIMIT_ERR, 
    ABANDON_ERR, 
    CREATE_ENTRY_ERR, 
    TIMEOUT_ERR, 
    SIZE_ERR, 
    GET_SIZE_ERR
};   


struct exception {
    enum type_of_result type; 
    int  rc; 
};

/* query cache structs */
/* query */

typedef struct Query_s {
	Filter* 	filter; 	/* Search Filter */
	AttributeName* 	attrs;		/* Projected attributes */
	struct berval 	base; 		/* Search Base */
	int 		scope;		/* Search scope */
} Query;

/* struct representing a cached query */
typedef struct cached_query_s {
	Query 				query;		/* LDAP query */ 
	char*  				q_uuid;		/* query identifier */ 
	int 				template_id;	/* template of the query */ 
	time_t 				expiry_time;	/* time till the query is considered valid */ 
	struct cached_query_s  		*next;  	/* next query in the template */
	struct cached_query_s  		*prev;  	/* previous query in the template */
	struct cached_query_s           *lru_up;	/* previous query in the LRU list */ 
	struct cached_query_s           *lru_down;	/* next query in the LRU list */ 
} CachedQuery; 

/* struct representing a query template
 * e.g. template string = &(cn=)(mail=) 
 */
typedef struct query_template_s {
	char* 		querystr;	/* Filter string corresponding to the QT */
	char* 		base;		/* Search base */ 
	int 		attr_set_index; /* determines the projected attributes */ 

	CachedQuery* 	query;	        /* most recent query cached for the template */	
	CachedQuery* 	query_last;     /* oldest query cached for the template */		

	int 		no_of_queries;  /* Total number of queries in the template */
	long 		ttl;		/* TTL for the queries of this template */ 
        ldap_pvt_thread_rdwr_t t_rwlock; /* Rd/wr lock for accessing queries in the template */ 
} QueryTemplate;

/* 
 * Represents a set of projected attributes and any
 * supersets among all specified sets of attributes. 
 */

struct attr_set {
	AttributeName*	attrs; 		/* specifies the set */
	int 		count;		/* number of attributes */ 
	int*		ID_array;	/* array of indices of supersets of 'attrs' */ 
};

struct query_manager_s; 

/* prototypes for functions for 1) query containment 
 * 2) query addition, 3) cache replacement 
 */
typedef int 	(*QCfunc)(struct query_manager_s*, Query*, int );
typedef void  	(*AddQueryfunc)(struct query_manager_s*, Query*, int, char*, struct exception* );
typedef char*  	(*CRfunc)(struct query_manager_s* );

/* LDAP query cache */ 
typedef struct query_manager_s {
	struct attr_set* 	attr_sets;		/* possible sets of projected attributes */
	QueryTemplate*	  	templates;		/* cacheable templates */

	CachedQuery*		lru_top;		/* top and bottom of LRU list */
	CachedQuery*		lru_bottom;

	ldap_pvt_thread_mutex_t		lru_mutex;	/* mutex for accessing LRU list */

	/* Query cache methods */
	QCfunc			qcfunc;			/* Query containment*/  
	CRfunc 			crfunc; 		/* cache replacement */
	AddQueryfunc		addfunc;		/* add query */ 
} query_manager; 

/* LDAP query cache manager */ 
typedef struct cache_manager_s {
	unsigned long   cache_size;			/* current cache size (bytes) */ 
	unsigned long 	thresh_hi;			/* cache capacity (bytes) */
	unsigned long   thresh_lo;			/* lower threshold for cache replacement */
	unsigned long	num_cached_queries; 		/* total number of cached queries */
	unsigned long   max_queries;			/* upper bound on # of cached queries */ 
	int     caching; 

	int 	numattrsets;			/* number of attribute sets */
	int 	numtemplates;			/* number of cacheable templates */
	int 	total_entries;			/* total number of entries cached */ 
        int     num_entries_limit;		/* max # of entries in a cacheable query */ 
	int     threads;			/* number of threads currently in meta_back_search */ 

	int     cc_period;		/* interval between successive consistency checks (sec) */ 
	int     cc_thread_started; 
	ldap_pvt_thread_t   cc_thread; 

	ldap_pvt_thread_mutex_t		cache_mutex;		
	ldap_pvt_thread_mutex_t		remove_mutex;
	ldap_pvt_thread_mutex_t		cc_mutex; 	

	query_manager*   qm;	/* query cache managed by the cache manager */ 
} cache_manager; 

/* search-cache.c */
int
meta_back_cache_search(
    Operation		*op,
    SlapReply		*rs
); 

/* config-cache.c */
int
meta_back_cache_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
); 

/* query-cache.c */
int 	query_containment(query_manager*, Query*, int); 
void 	add_query(query_manager*, Query*, int, char*, struct exception*);
char* 	cache_replacement(query_manager*);
void 	remove_from_template (CachedQuery*, QueryTemplate*); 
void 	remove_query (query_manager*, CachedQuery*);
void 	free_query (CachedQuery*); 

/* substring.c */
int 	substr_containment_substr(Filter*, Filter*); 
int 	substr_containment_equality(Filter*, Filter*); 

/* template.c */
void 
filter2template( Filter *f, 
		 struct berval *fstr, 
		 AttributeName** filter_attrs, 
		 int* filter_cnt, 
		 struct exception* result
);

/* merge.c */

int
merge_entry (
	    Operation		*op, 
	    SlapReply		*rs,
	    struct berval	*query_uuid, 
	    struct exception	*result
); 

int 
get_entry_size(Entry* e, 
	       int size_init, 
	       struct exception* result
); 

/* remove.c */
int 
remove_query_data (
		   Operation* conn,
		   SlapReply *rs,
		   struct berval* query_uuid, 
		   struct exception* result
);
#endif

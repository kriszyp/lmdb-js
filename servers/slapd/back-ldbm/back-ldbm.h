/* back-ldbm.h - ldap ldbm back-end header file */

#ifndef _BACK_LDBM_H_
#define _BACK_LDBM_H_

#include "ldbm.h"

LDAP_BEGIN_DECL

#define DEFAULT_CACHE_SIZE	1000

#ifdef HAVE_BERKELEY_DB2
#	define DEFAULT_DBCACHE_SIZE (100 * DEFAULT_DB_PAGE_SIZE)
#else
#	define DEFAULT_DBCACHE_SIZE 100000
#endif

#define DEFAULT_DB_DIRECTORY	"/usr/tmp"
#define DEFAULT_MODE		0600

#define SUBLEN			3

/*
 * there is a single index for each attribute.  these prefixes insure
 * that there is no collision among keys.
 */
#define EQ_PREFIX	'='	/* prefix for equality keys     */
#define APPROX_PREFIX	'~'	/* prefix for approx keys       */
#define SUB_PREFIX	'*'	/* prefix for substring keys    */
#define CONT_PREFIX	'\\'	/* prefix for continuation keys */

#define DEFAULT_BLOCKSIZE	8192

/*
 * This structure represents an id block on disk and an id list
 * in core.
 *
 * The fields have the following meanings:
 *
 *	b_nmax	maximum number of ids in this block. if this is == ALLIDSBLOCK,
 *		then this block represents all ids.
 *	b_nids	current number of ids in use in this block.  if this
 *		is == INDBLOCK, then this block is an indirect block
 *		containing a list of other blocks containing actual ids.
 *		the list is terminated by an id of NOID.
 *	b_ids	a list of the actual ids themselves
 */
typedef struct block {
	ID		b_nmax;		/* max number of ids in this list  */
#define ALLIDSBLOCK	0		/* == 0 => this is an allid block  */
	ID		b_nids;		/* current number of ids used	   */
#define INDBLOCK	0		/* == 0 => this is an indirect blk */
	ID		b_ids[1];	/* the ids - actually bigger 	   */
} Block, IDList;

#define ALLIDS( idl )		((idl)->b_nmax == ALLIDSBLOCK)
#define INDIRECT_BLOCK( idl )	((idl)->b_nids == INDBLOCK)

/* for the in-core cache of entries */
struct cache {
	int		c_maxsize;
	int		c_cursize;
	Avlnode		*c_dntree;
	Avlnode		*c_idtree;
	Entry		*c_lruhead;	/* lru - add accessed entries here */
	Entry		*c_lrutail;	/* lru - rem lru entries from here */
	pthread_mutex_t	c_mutex;
};

/* for the cache of open index files */
struct dbcache {
	char		*dbc_name;
	int		dbc_refcnt;
	time_t		dbc_lastref;
	pthread_mutex_t	dbc_mutex;
	pthread_cond_t	dbc_cv;
	int		dbc_readers;
	long		dbc_blksize;
	int		dbc_maxids;
	int		dbc_maxindirect;
	LDBM		dbc_db;
};

/* for the cache of attribute information (which are indexed, etc.) */
struct attrinfo {
	char	*ai_type;	/* type name (cn, sn, ...)	*/
	int	ai_indexmask;	/* how the attr is indexed	*/
#define INDEX_PRESENCE	0x01
#define INDEX_EQUALITY	0x02
#define INDEX_APPROX	0x04
#define INDEX_SUB	0x08
#define INDEX_UNKNOWN	0x10
#define INDEX_FROMINIT	0x20
	int	ai_syntaxmask;	/* what kind of syntax		*/
/* ...from slap.h...
#define SYNTAX_CIS      0x01
#define SYNTAX_CES      0x02
#define SYNTAX_BIN      0x04
   ... etc. ...
*/
};

#define MAXDBCACHE	10

struct ldbminfo {
	ID			li_nextid;
	pthread_mutex_t		li_nextid_mutex;
	int			li_mode;
	char			*li_directory;
	struct cache		li_cache;
	Avlnode			*li_attrs;
	int			li_dbcachesize;
	int			li_flush_wrt;
	struct dbcache		li_dbcache[MAXDBCACHE];
	pthread_mutex_t		li_dbcache_mutex;
	pthread_cond_t		li_dbcache_cv;
};

#include "proto-back-ldbm.h"

LDAP_END_DECL

#endif /* _back_ldbm_h_ */

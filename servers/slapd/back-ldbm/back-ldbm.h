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

#define UNKNOWN_PREFIX	'?'	/* prefix for unknown keys    */

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

typedef ID ID_BLOCK;

#define ID_BLOCK_NMAX_OFFSET	0
#define ID_BLOCK_NIDS_OFFSET	1
#define ID_BLOCK_IDS_OFFSET		2

/* all ID_BLOCK macros operate on a pointer to a ID_BLOCK */

#define ID_BLOCK_NMAX(b)		((b)[ID_BLOCK_NMAX_OFFSET])
#define ID_BLOCK_NIDS(b)		((b)[ID_BLOCK_NIDS_OFFSET])
#define ID_BLOCK_ID(b, n)		((b)[ID_BLOCK_IDS_OFFSET+(n)])

#define ID_BLOCK_NOID(b, n)		(ID_BLOCK_ID((b),(n)) == NOID)

#define ID_BLOCK_ALLIDS_VALUE	0
#define ID_BLOCK_ALLIDS(b)		(ID_BLOCK_NMAX(b) == ID_BLOCK_ALLIDS_VALUE)

#define ID_BLOCK_INDIRECT_VALUE	0
#define ID_BLOCK_INDIRECT(b)	(ID_BLOCK_NIDS(b) == ID_BLOCK_INDIRECT_VALUE)

/* for the in-core cache of entries */
struct cache {
	int		c_maxsize;
	int		c_cursize;
	Avlnode		*c_dntree;
	Avlnode		*c_idtree;
	Entry		*c_lruhead;	/* lru - add accessed entries here */
	Entry		*c_lrutail;	/* lru - rem lru entries from here */
	ldap_pvt_thread_mutex_t	c_mutex;
};

#define CACHE_READ_LOCK		0
#define CACHE_WRITE_LOCK	1

/* for the cache of open index files */
struct dbcache {
	int		dbc_refcnt;
	int		dbc_maxids;
	int		dbc_maxindirect;
	time_t	dbc_lastref;
	long	dbc_blksize;
	char	*dbc_name;
	LDBM	dbc_db;
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

/* this could be made an option */
#ifndef SLAPD_NEXTID_CHUNK
#define SLAPD_NEXTID_CHUNK	32
#endif

struct ldbminfo {
	ID			li_nextid;
#if SLAPD_NEXTID_CHUNK > 1
	ID			li_nextid_wrote;
#endif
	char		*li_nextid_file;
	ldap_pvt_thread_mutex_t		li_root_mutex;
	ldap_pvt_thread_mutex_t		li_add_mutex;
	ldap_pvt_thread_mutex_t		li_nextid_mutex;
	int			li_mode;
	char			*li_directory;
	struct cache		li_cache;
	Avlnode			*li_attrs;
	int			li_dbcachesize;
	int			li_dbcachewsync;
	struct dbcache		li_dbcache[MAXDBCACHE];
	ldap_pvt_thread_mutex_t		li_dbcache_mutex;
	ldap_pvt_thread_cond_t		li_dbcache_cv;
#ifdef HAVE_BERKELEY_DB2
	DB_ENV                      li_db_env;
#endif
};

extern int ldbm_ignore_nextid_file;

LDAP_END_DECL

#include "proto-back-ldbm.h"

#endif /* _back_ldbm_h_ */

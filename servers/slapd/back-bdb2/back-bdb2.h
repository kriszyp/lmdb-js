/* back-bdb2.h - ldap bdb2 back-end header file */

#ifndef _BACK_BDB2_H_
#define _BACK_BDB2_H_

#include "ldbm.h"
#include "db.h"

LDAP_BEGIN_DECL

#define DEFAULT_CACHE_SIZE	1000

/*  since DEFAULT_DB_PAGE_SIZE is 1K, we have 128K,
	which is suggested by Sleepycat  */
#define DEFAULT_DBCACHE_SIZE (128 * DEFAULT_DB_PAGE_SIZE)

#define DEFAULT_DB_DIRECTORY	"/usr/tmp"
#define DEFAULT_DB_HOME         "/usr/tmp"
#define DEFAULT_MODE		0600

#define SUBLEN			3

#define BDB2_SUFFIX     ".dbb"


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

/* for the cache of open index files (re-used for txn) */
struct dbcache {
	int			dbc_refcnt;
	int			dbc_maxids;
	int			dbc_maxindirect;
	time_t		dbc_lastref;
	long		dbc_blksize;
	char		*dbc_name;
	LDBM		dbc_db;

	struct dbcache   *next;
};

typedef  struct dbcache  BDB2_TXN_FILES;


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


/*  TP stuff  */

typedef  struct _bdb2_txn_head {

	/*  counter and timer to control checkpoints  */
	size_t           txn_cnt;
	time_t           txn_chkp;

	/*  a list of all DB files in use  */
	BDB2_TXN_FILES   *dbFiles;

	/*  we have five fixed files  */
#define  BDB2_DB_DN_FILE            0
#define  BDB2_DB_DN2ID_FILE         1
#define  BDB2_DB_ID2ENTRY_FILE      2
#define  BDB2_DB_ID2CHILDREN_FILE   3
#define  BDB2_DB_OC_IDX_FILE        4

	/*  is the default attribute index set to non-none  */
	int              withDefIDX;
#define  BDB2_WITH_DEF_IDX          1

} BDB2_TXN_HEAD;


/*  end of TP stuff  */


/*  the private description of a backend type  */
struct ldbtype {
	char			*lty_dbhome;
	size_t			lty_mpsize;

	/*  XXX do we need a private DB_ENV for all DB2 backend types ?  */
	DB_ENV			*lty_dbenv;
};

#define get_dbenv(be) ((struct ldbtype *) (be)->bd_info->bi_private)->lty_dbenv


/*  the private description of a database  */
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

	/*  a list of all files of the database  */
	BDB2_TXN_HEAD		li_txn_head;

};


#include "proto-back-bdb2.h"

LDAP_END_DECL

#endif /* _back_bdb2_h_ */

/* back-bdb2.h - ldap bdb2 back-end header file */
/* $OpenLDAP$ */

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

#define DN_BASE_PREFIX		'='
#define DN_ONE_PREFIX		'@'
#define DN_SUBTREE_PREFIX	'?'
    
#define SLAPD_FILTER_DN_ONE			((ber_tag_t) -2)
#define SLAPD_FILTER_DN_SUBTREE		((ber_tag_t) -3)


#define BDB2_SUFFIX     ".bdb2"


/*
 * there is a single index for each attribute.  these prefixes ensure
 * that there is no collision among keys.
 */
#define EQ_PREFIX	'='	/* prefix for equality keys     */
#define APPROX_PREFIX	'~'	/* prefix for approx keys       */
#define SUB_PREFIX	'*'	/* prefix for substring keys    */
#define CONT_PREFIX	'\\'	/* prefix for continuation keys */

/* allow 3 characters per byte + PREFIX + EOS */
#define CONT_SIZE	( sizeof(long)*3 + 1 + 1 )


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

/* for the cache of open index files (re-used for txn) */
struct dbcache {
	int			dbc_refcnt;
	int			dbc_maxids;
	int			dbc_maxindirect;
	long		dbc_blksize;
	char		*dbc_name;
	LDBM		dbc_db;

	struct dbcache   *next;
};

typedef  struct dbcache  BDB2_TXN_FILES;
typedef  struct dbcache DBCache;


/* for the cache of attribute information (which are indexed, etc.) */
struct attrinfo {
	char	*ai_type;	/* type name (cn, sn, ...)	*/
	int	ai_indexmask;	/* how the attr is indexed	*/
#define INDEX_PRESENCE	0x0001
#define INDEX_EQUALITY	0x0002
#define INDEX_APPROX	0x0004
#define INDEX_SUB		0x0008
#define INDEX_UNKNOWN	0x0010
#define INDEX_FROMINIT	0x1000
	int	ai_syntaxmask;	/* what kind of syntax		*/
/* ...from slap.h...
#define SYNTAX_CIS      0x01
#define SYNTAX_CES      0x02
#define SYNTAX_BIN      0x04
   ... etc. ...
*/
};

/*  TP stuff  */

typedef  struct _bdb2_txn_head {

	/*  log size and timer to control checkpoints  */
	u_int32_t        txn_log;
	u_int32_t        txn_time;

	/*  a list of all DB files in use  */
	BDB2_TXN_FILES   *dbFiles;

	/*  we have five fixed files  */
#define  BDB2_DB_DN_FILE            0
#define  BDB2_DB_DN2ID_FILE         1
#define  BDB2_DB_ID2ENTRY_FILE      2
#define  BDB2_DB_ID2CHILDREN_FILE   3
#define  BDB2_DB_OC_IDX_FILE        4

	/*  a database handle for the NEXTID file
		(must be opened like all DB files at startup
		and closed on shutdown  */
	LDBM             nextidFile;

	/*  is the default attribute index set to non-none  */
	int              withDefIDX;
#define  BDB2_WITH_DEF_IDX          1

	/*  a handle for the backend's environment  */
	DB_ENV           **dbenvH;

} BDB2_TXN_HEAD;


/*  end of TP stuff  */


/*  the private description of a backend type  */
struct ldbtype {
	char			*lty_dbhome;
	size_t			lty_mpsize;
	int				lty_betiming;
};

#define with_timing(bi) (((struct ldbtype *) \
			(bi)->bi_private)->lty_betiming == 1)

/*  The DB environment  */
extern DB_ENV       bdb2i_dbEnv;


/*  the private description of a database  */
struct ldbminfo {
	ID			li_nextid;
	char		*li_nextid_file;
	int			li_mode;
	char			*li_directory;
	struct cache		li_cache;
	Avlnode			*li_attrs;
	int			li_dbcachesize;
	int			li_dbcachewsync;

	/*  a list of all files of the database  */
	BDB2_TXN_HEAD		li_txn_head;

};


#include "proto-back-bdb2.h"

LDAP_END_DECL

#endif /* _back_bdb2_h_ */

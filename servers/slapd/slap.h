/* slap.h - stand alone ldap server include file */

#ifndef _SLDAPD_H_
#define _SLDAPD_H_

#include <stdlib.h>

#ifndef LDAP_SYSLOG
#define LDAP_SYSLOG 1
#endif

#include <sys/types.h>
#include <ac/syslog.h>
#include <ac/regex.h>

#include "avl.h"

#ifndef ldap_debug
#define ldap_debug slap_debug
#endif


#include "ldap_log.h"

#include "../../libraries/liblber/lber-int.h"
#include "ldap.h"

#include "ldap_pvt_thread.h"
#include "ldif.h"
#ifdef f_next
#undef f_next /* name conflict between sys/file.h on SCO and struct filter */
#endif

#define DN_DNS	0
#define DN_X500	1

#define ON	1
#define OFF	(-1)
#define UNDEFINED 0

#define MAXREMATCHES 10

#define DNSEPARATOR(c)	((c) == ',' || (c) == ';')
#define SEPARATOR(c)	((c) == ',' || (c) == ';' || (c) == '+')
#define SPACE(c)	((c) == ' ' || (c) == '\n')
#define NEEDSESCAPE(c)	((c) == '\\' || (c) == '"')

LDAP_BEGIN_DECL

extern int slap_debug;

struct slap_op;
struct slap_conn;

/*
 * represents an attribute value assertion (i.e., attr=value)
 */
typedef struct ava {
	char		*ava_type;
	struct berval	ava_value;
} Ava;

/*
 * represents a search filter
 */
typedef struct filter {
	unsigned long	f_choice;	/* values taken from ldap.h */

	union {
		/* present */
		char		*f_un_type;

		/* equality, lessorequal, greaterorequal, approx */
		Ava		f_un_ava;

		/* and, or, not */
		struct filter	*f_un_complex;

		/* substrings */
		struct sub {
			char	*f_un_sub_type;
			char	*f_un_sub_initial;
			char	**f_un_sub_any;
			char	*f_un_sub_final;
		} f_un_sub;
	} f_un;
#define f_type		f_un.f_un_type
#define f_ava		f_un.f_un_ava
#define f_avtype	f_un.f_un_ava.ava_type
#define f_avvalue	f_un.f_un_ava.ava_value
#define f_and		f_un.f_un_complex
#define f_or		f_un.f_un_complex
#define f_not		f_un.f_un_complex
#define f_list		f_un.f_un_complex
#define f_sub		f_un.f_un_sub
#define f_sub_type	f_un.f_un_sub.f_un_sub_type
#define f_sub_initial	f_un.f_un_sub.f_un_sub_initial
#define f_sub_any	f_un.f_un_sub.f_un_sub_any
#define f_sub_final	f_un.f_un_sub.f_un_sub_final

	struct filter	*f_next;
} Filter;

/*
 * represents an attribute (type + values + syntax)
 */
typedef struct attr {
	char		*a_type;
	struct berval	**a_vals;
	int		a_syntax;
	struct attr	*a_next;
} Attribute;

/*
 * the attr_syntax() routine returns one of these values
 * telling what kind of syntax an attribute supports.
 */
#define SYNTAX_CIS	0x01	/* case insensitive string		*/
#define SYNTAX_CES	0x02	/* case sensitive string		*/
#define SYNTAX_BIN	0x04	/* binary data 				*/
#define SYNTAX_TEL	0x08	/* telephone number string		*/
#define SYNTAX_DN	0x10	/* dn string				*/

/*
 * the id used in the indexes to refer to an entry
 */
typedef unsigned long	ID;
#define NOID	((unsigned long)-1)

/*
 * represents an entry in core
 */
typedef struct entry {
	/*
	 * The ID field should only be changed before entry is
	 * inserted into a cache.  The ID value is backend
	 * specific.
	 */
	ID		e_id;

	char		*e_dn;		/* DN of this entry */
	char		*e_ndn;		/* normalized DN of this entry */
	Attribute	*e_attrs;	/* list of attributes + values */

	/* for use by the backend for any purpose */
	void*	e_private;
} Entry;

/*
 * represents an access control list
 */

/* the "by" part */
struct access {
#define ACL_NONE	0x01
#define ACL_COMPARE	0x02
#define ACL_SEARCH	0x04
#define ACL_READ	0x08
#define ACL_WRITE	0x10
#define ACL_SELF	0x40
	int			a_access;

	char		*a_dnpat;
	char		*a_addrpat;
	char		*a_domainpat;
	char		*a_dnattr;

#ifdef SLAPD_ACLGROUPS
        char		*a_group;
        char		*a_objectclassvalue;
        char		*a_groupattrname;
#endif
	struct access	*a_next;
};

/* the "to" part */
struct acl {
	/* "to" part: the entries this acl applies to */
	Filter		*acl_filter;
	regex_t		acl_dnre;
	char		*acl_dnpat;
	char		**acl_attrs;

	/* "by" part: list of who has what access to the entries */
	struct access	*acl_access;

	struct acl	*acl_next;
};

/*
 * A list of LDAPMods
 */
typedef struct ldapmodlist {
	struct ldapmod ml_mod;
	struct ldapmodlist *ml_next;
#define ml_op		ml_mod.mod_op
#define ml_type		ml_mod.mod_type
#define ml_values	ml_mod.mod_values
#define ml_bvalues	ml_mod.mod_bvalues
} LDAPModList;

/*
 * represents schema information for a database
 */

struct objclass {
	char		*oc_name;
	char		**oc_required;
	char		**oc_allowed;
	struct objclass	*oc_next;
};

/*
 * Backend-info
 * represents a backend 
 */

typedef struct backend_info BackendInfo;	/* per backend type */
typedef struct backend_db BackendDB;		/* per backend database */

extern int nBackendInfo;
extern int nBackendDB;
extern BackendInfo	*backendInfo;
extern BackendDB	*backendDB;

extern int			slapMode;	
#define SLAP_UNDEFINED_MODE	0
#define SLAP_SERVER_MODE	1
#define SLAP_TOOL_MODE		2
#ifdef SLAPD_BDB2
#  define SLAP_TIMEDSERVER_MODE  3
#  define SLAP_TOOLID_MODE       4
#endif

/* temporary aliases */
typedef BackendDB Backend;
#define nbackends nBackendDB
#define backends backendDB

struct backend_db {
	BackendInfo	*bd_info;	/* pointer to shared backend info */

	/* BackendInfo accessors */
#define		be_config	bd_info->bi_db_config
#define		be_type		bd_info->bi_type

#define		be_bind		bd_info->bi_op_bind
#define		be_unbind	bd_info->bi_op_unbind
#define		be_add		bd_info->bi_op_add
#define		be_compare	bd_info->bi_op_compare
#define		be_delete	bd_info->bi_op_delete
#define		be_modify	bd_info->bi_op_modify
#define		be_modrdn	bd_info->bi_op_modrdn
#define		be_search	bd_info->bi_op_search

#define		be_group	bd_info->bi_acl_group

	/* these should be renamed from be_ to bd_ */
	char	**be_suffix;	/* the DN suffixes of data in this backend */
	char    **be_suffixAlias;       /* the DN suffix aliases of data in this backend */
	char	*be_root_dn;	/* the magic "root" dn for this db 	*/
	char	*be_root_ndn;	/* the magic "root" normalized dn for this db	*/
	char	*be_root_pw;	/* the magic "root" password for this db	*/
	int	be_readonly;	/* 1 => db is in "read only" mode	   */
	int     be_maxDerefDepth;       /* limit for depth of an alias deref  */
	int	be_sizelimit;	/* size limit for this backend   	   */
	int	be_timelimit;	/* time limit for this backend       	   */
	struct acl *be_acl;	/* access control list for this backend	   */
	int	be_dfltaccess;	/* access given if no acl matches	   */
	char	**be_replica;	/* replicas of this backend (in master)	   */
	char	*be_replogfile;	/* replication log file (in master)	   */
	char	*be_update_ndn;	/* allowed to make changes (in replicas)   */
	int	be_lastmod;	/* keep track of lastmodified{by,time}	   */

	void	*be_private;	/* anything the backend database needs 	   */
};

struct backend_info {
	char	*bi_type;	/* type of backend */

	/*
	 * per backend type routines:
	 * bi_init: called to allocate a backend_info structure,
	 *		called once BEFORE configuration file is read.
	 *		bi_init() initializes this structure hence is
	 *		called directly from be_initialize()
	 * bi_config: called per 'backend' specific option
	 *		all such options must before any 'database' options
	 *		bi_config() is called only from read_config()
	 * bi_open: called to open each database, called
	 *		once AFTER configuration file is read but
	 *		BEFORE any bi_db_open() calls.
	 *		bi_open() is called from backend_startup()
	 * bi_close: called to close each database, called
	 *		once during shutdown after all bi_db_close calls.
	 *		bi_close() is called from backend_shutdown()
	 * bi_destroy: called to destroy each database, called
	 *		once during shutdown after all bi_db_destroy calls.
	 *		bi_destory() is called from backend_destroy()
	 */
	int (*bi_init)	LDAP_P((BackendInfo *bi));
	int	(*bi_config) LDAP_P((BackendInfo *bi,
		char *fname, int lineno, int argc, char **argv ));
	int (*bi_open) LDAP_P((BackendInfo *bi));
	int (*bi_close) LDAP_P((BackendInfo *bi));
	int (*bi_destroy) LDAP_P((BackendInfo *bi));

	/*
	 * per database routines:
	 * bi_db_init: called to initialize each database,
	 *	called upon reading 'database <type>' 
	 *	called only from backend_db_init()
	 * bi_db_config: called to configure each database,
	 *  called per database to handle per database options
	 *	called only from read_config()
	 * bi_db_open: called to open each database
	 *	called once per database immediately AFTER bi_open()
	 *	calls but before daemon startup.
	 *  called only by backend_startup()
	 * bi_db_close: called to close each database
	 *	called once per database during shutdown but BEFORE
	 *  any bi_close call.
	 *  called only by backend_shutdown()
	 * bi_db_destroy: called to destroy each database
	 *  called once per database during shutdown AFTER all
	 *  bi_close calls but before bi_destory calls.
	 *  called only by backend_destory()
	 */
	int (*bi_db_init) LDAP_P((Backend *bd));
	int	(*bi_db_config) LDAP_P((Backend *bd,
		char *fname, int lineno, int argc, char **argv ));
	int (*bi_db_open) LDAP_P((Backend *bd));
	int (*bi_db_close) LDAP_P((Backend *bd));
	int (*bi_db_destroy) LDAP_P((Backend *db));

	/* LDAP Operations Handling Routines */
	int	(*bi_op_bind)  LDAP_P(( BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *dn, int method, struct berval *cred, char** edn ));
	int (*bi_op_unbind) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o ));
	int	(*bi_op_search) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *base, int scope, int deref, int slimit, int tlimit,
		Filter *f, char *filterstr, char **attrs, int attrsonly));
	int	(*bi_op_compare)LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *dn, Ava *ava));
	int	(*bi_op_modify) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *dn, LDAPModList *m));
	int	(*bi_op_modrdn) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *dn, char *newrdn, int deleteoldrdn,
		char *newSuperior));
	int	(*bi_op_add)    LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		Entry *e));
	int	(*bi_op_delete) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		char *dn));
	/* Bug: be_op_abandon in unused! */
	int	(*bi_op_abandon) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		int msgid));

	/* Auxilary Functions */
#ifdef SLAPD_ACLGROUPS
	int	(*bi_acl_group)  LDAP_P((Backend *bd,
		Entry *e, char *bdn, char *edn,
		char *objectclassValue, char *groupattrName ));
#endif

	unsigned int bi_nDB;	/* number of databases of this type */
	void	*bi_private;	/* anything the backend type needs */
};

/*
 * represents an operation pending from an ldap client
 */

typedef struct slap_op {
	long	o_opid;		/* id of this operation		  */
	long	o_msgid;	/* msgid of the request		  */

	ldap_pvt_thread_t	o_tid;		/* thread handling this op	  */

	BerElement	*o_ber;		/* ber of the request		  */

	unsigned long	o_tag;		/* tag of the request		  */
	time_t		o_time;		/* time op was initiated	  */
	char		*o_dn;		/* dn bound when op was initiated */
	char		*o_ndn;		/* normalized dn bound when op was initiated */
	int			o_authtype;	/* auth method used to bind dn	  */
					/* values taken from ldap.h	  */
					/* LDAP_AUTH_*			  */

/*	 long	o_connid;	*//* id of conn initiating this op  */

#ifdef LDAP_CONNECTIONLESS
	int		o_cldap;	/* != 0 if this came in via CLDAP */
	struct sockaddr	o_clientaddr;	/* client address if via CLDAP	  */
	char		o_searchbase;	/* search base if via CLDAP	  */
#endif

	ldap_pvt_thread_mutex_t	o_abandonmutex; /* protects o_abandon  */
	int		o_abandon;	/* abandon flag */

	struct slap_op	*o_next;	/* next operation in list	  */
	void	*o_private;	/* anything the backend needs	  */
} Operation;

/*
 * represents a connection from an ldap client
 */

typedef struct slap_conn {
	int			c_struct_state; /* structure management state */
	int			c_conn_state;	/* connection state */

	ldap_pvt_thread_mutex_t	c_mutex; /* protect the connection */
	Sockbuf		c_sb;		/* ber connection stuff		  */

	/* only can be changed by connect_init */
	time_t		c_starttime;	/* when the connection was opened */
	long		c_connid;	/* id of this connection for stats*/
	char		*c_client_addr;	/* address of client */
	char		*c_client_name;	/* name of client */

	/* only can be changed by binding thread */
	char	*c_cdn;		/* DN provided by the client */
	char	*c_dn;		/* DN bound to this conn  */
	int		c_protocol;	/* version of the LDAP protocol used by client */
	int		c_authtype;	/* auth method used to bind c_dn  */
#ifdef LDAP_COMPAT
	int		c_version;	/* for compatibility w/2.0, 3.0	  */
#endif

	Operation	*c_ops;			/* list of operations being processed */
	Operation	*c_pending_ops;	/* list of pending operations */

	ldap_pvt_thread_mutex_t	c_write_mutex;	/* only one pdu written at a time */
	ldap_pvt_thread_cond_t	c_write_cv;		/* used to wait for sd write-ready*/

	BerElement	*c_currentber;	/* ber we're attempting to read */
	int		c_writewaiter;	/* true if writer is waiting */

	long	c_n_ops_received;		/* num of ops received (next op_id) */
	long	c_n_ops_executing;	/* num of ops currently executing */
	long	c_n_ops_pending;		/* num of ops pending execution */
	long	c_n_ops_completed;	/* num of ops completed */
} Connection;

#if defined(LDAP_SYSLOG) && defined(LDAP_DEBUG)
#define Statslog( level, fmt, connid, opid, arg1, arg2, arg3 )	\
	{ \
		if ( ldap_debug & level ) \
			fprintf( stderr, fmt, connid, opid, arg1, arg2, arg3 );\
		if ( ldap_syslog & level ) \
			syslog( ldap_syslog_level, fmt, connid, opid, arg1, \
			    arg2, arg3 ); \
	}
#else
#define Statslog( level, fmt, connid, opid, arg1, arg2, arg3 )
#endif

#include "proto-slap.h"

LDAP_END_DECL

#endif /* _slap_h_ */

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

#undef NDEBUG
#include <assert.h>

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

#ifdef SLAPD_BDB2
extern int bdb2i_do_timing;
#endif

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
	char		*e_dn;		/* DN of this entry 		  */
	char		*e_ndn;		/* normalized DN of this entry	  */
	Attribute	*e_attrs;	/* list of attributes + values    */

	ID		e_id;		/* id of this entry - this should */
					/* really be private to back-ldbm */
	char		e_state;	/* for the cache		  */

	ldap_pvt_thread_rdwr_t	e_rdwr;	/* reader/writer lock             */

#define ENTRY_STATE_DELETED	1
#define ENTRY_STATE_CREATING	2
	int		e_refcnt;	/* # threads ref'ing this entry   */
	struct entry	*e_lrunext;	/* for cache lru list		  */
	struct entry	*e_lruprev;
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
 * represents a "database"
 */

typedef struct backend Backend;
struct backend {
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
	char	*be_type;	/* type of database			   */

	void	*be_private;	/* anything the backend needs 		   */

	/* backend routines */
	int	(*be_bind)   LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *dn, int method, struct berval *cred, char** edn ));
	void	(*be_unbind) LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o ));
	int	(*be_search) LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *base, int scope, int deref, int slimit, int tlimit,
		Filter *f, char *filterstr, char **attrs, int attrsonly));
	int	(*be_compare)LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *dn, Ava *ava));
	int	(*be_modify) LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *dn, LDAPModList *m));
	int	(*be_modrdn) LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *dn, char *newrdn, int deleteoldrdn ));
	int	(*be_add)    LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		Entry *e));
	int	(*be_delete) LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		char *dn));
	/* Bug: be_abandon in unused! */
	void	(*be_abandon)LDAP_P((Backend *be,
		struct slap_conn *c, struct slap_op *o,
		int msgid));
	void	(*be_config) LDAP_P((Backend *be,
		char *fname, int lineno, int argc, char **argv ));
	void	(*be_init)   LDAP_P((Backend *be));
	void	(*be_startup)   LDAP_P((Backend *be));
	void	(*be_shutdown)  LDAP_P((Backend *be));
	void	(*be_close)  LDAP_P((Backend *be));

#ifdef SLAPD_ACLGROUPS
	int	(*be_group)  LDAP_P((Backend *be, Entry *e,
		char *bdn, char *edn,
		char *objectclassValue, char *groupattrName ));
#endif
};

/*
 * represents an operation pending from an ldap client
 */

typedef struct slap_op {
	BerElement	*o_ber;		/* ber of the request		  */
	long		o_msgid;	/* msgid of the request		  */
	unsigned long	o_tag;		/* tag of the request		  */
	time_t		o_time;		/* time op was initiated	  */
	char		*o_dn;		/* dn bound when op was initiated */
	char		*o_ndn;		/* normalized dn bound when op was initiated */
	int		o_authtype;	/* auth method used to bind dn	  */
					/* values taken from ldap.h	  */
					/* LDAP_AUTH_*			  */
	int		o_opid;		/* id of this operation		  */
	int		o_connid;	/* id of conn initiating this op  */
#ifdef LDAP_CONNECTIONLESS
	int		o_cldap;	/* != 0 if this came in via CLDAP */
	struct sockaddr	o_clientaddr;	/* client address if via CLDAP	  */
	char		o_searchbase;	/* search base if via CLDAP	  */
#endif
	struct slap_op	*o_next;	/* next operation pending	  */
	ldap_pvt_thread_t	o_tid;		/* thread handling this op	  */
	int		o_abandon;	/* signals op has been abandoned  */
	ldap_pvt_thread_mutex_t	o_abandonmutex;	/* signals op has been abandoned  */

	void	*o_private;	/* anything the backend needs	  */
} Operation;

/*
 * represents a connection from an ldap client
 */

typedef struct slap_conn {
	Sockbuf		c_sb;		/* ber connection stuff		  */
	char		*c_cdn;		/* DN provided by the client */
	char		*c_dn;		/* DN bound to this conn  */
	ldap_pvt_thread_mutex_t	c_dnmutex;	/* mutex for c_dn field		  */
	int		c_protocol;	/* version of the LDAP protocol used by client */
	int		c_authtype;	/* auth method used to bind c_dn  */
#ifdef LDAP_COMPAT
	int		c_version;	/* for compatibility w/2.0, 3.0	  */
#endif
	char		*c_addr;	/* address of client on this conn */
	char		*c_domain;	/* domain of client on this conn  */
	Operation	*c_ops;		/* list of pending operations	  */
	ldap_pvt_thread_mutex_t	c_opsmutex;	/* mutex for c_ops list & stats	  */
	ldap_pvt_thread_mutex_t	c_pdumutex;	/* only one pdu written at a time */
	ldap_pvt_thread_cond_t	c_wcv;		/* used to wait for sd write-ready*/
	int		c_gettingber;	/* in the middle of ber_get_next  */
	BerElement	*c_currentber;	/* ber we're getting              */
	int		c_writewaiter;	/* signals write-ready sd waiter  */
	int		c_pduwaiters;	/* signals threads waiting 4 pdu  */
	time_t		c_starttime;	/* when the connection was opened */
	int		c_connid;	/* id of this connection for stats*/
	int		c_opsinitiated;	/* # ops initiated/next op id	  */
	int		c_opscompleted;	/* # ops completed		  */
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

/* slap.h - stand alone ldap server include file */

#ifndef _SLDAPD_H_
#define _SLDAPD_H_

#define LDAP_SYSLOG

#include <syslog.h>
#include <sys/types.h>
#include <regex.h>

#include "avl.h"
#include "lber.h"
#include "ldap.h"
#include "lthread.h"
#include "ldif.h"

#define DN_DNS	0
#define DN_X500	1

#define ON	1
#define OFF	(-1)
#define UNDEFINED 0

#define MAXREMATCHES 10

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
	Attribute	*e_attrs;	/* list of attributes + values    */

	ID		e_id;		/* id of this entry - this should */
					/* really be private to back-ldbm */
	char		e_state;	/* for the cache		  */
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
	char		*a_dnpat;
	char		*a_addrpat;
	char		*a_domainpat;
	char		*a_dnattr;
	long		a_access;

#ifdef ACLGROUP
    char		*a_group;
#endif

#define ACL_NONE	0x01
#define ACL_COMPARE	0x02
#define ACL_SEARCH	0x04
#define ACL_READ	0x08
#define ACL_WRITE	0x10
#define ACL_SELF	0x40
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

typedef struct backend {
	char	**be_suffix;	/* the DN suffixes of data in this backend */
	char	*be_rootdn;	/* the magic "root" dn for this db   	   */
	char	*be_rootpw;	/* the magic "root" password for this db   */
	int	be_readonly;	/* 1 => db is in "read only" mode	   */
	int	be_sizelimit;	/* size limit for this backend   	   */
	int	be_timelimit;	/* time limit for this backend       	   */
	struct acl *be_acl;	/* access control list for this backend	   */
	int	be_dfltaccess;	/* access given if no acl matches	   */
	char	**be_replica;	/* replicas of this backend (in master)	   */
	char	*be_replogfile;	/* replication log file (in master)	   */
	char	*be_updatedn;	/* allowed to make changes (in replicas)   */
	int	be_lastmod;	/* keep track of lastmodified{by,time}	   */
	char	*be_type;	/* type of database			   */

	void	*be_private;	/* anything the backend needs 		   */

	IFP	be_bind;	/* backend bind routine			   */
	IFP	be_unbind;	/* backend unbind routine 		   */
	IFP	be_search;	/* backend search routine 		   */
	IFP	be_compare;	/* backend compare routine 		   */
	IFP	be_modify;	/* backend modify routine 		   */
	IFP	be_modrdn;	/* backend modrdn routine 		   */
	IFP	be_add;		/* backend add routine			   */
	IFP	be_delete;	/* backend delete routine 		   */
	IFP	be_abandon;	/* backend abandon routine 		   */
	IFP	be_config;	/* backend config routine	   	   */
	IFP	be_init;	/* backend init routine			   */
	IFP	be_close;	/* backend close routine		   */

#ifdef ACLGROUP
	IFP	be_group;	/* backend group member test               */
#endif
} Backend;

/*
 * represents an operation pending from an ldap client
 */

typedef struct op {
	BerElement	*o_ber;		/* ber of the request		  */
	long		o_msgid;	/* msgid of the request		  */
	unsigned long	o_tag;		/* tag of the request		  */
	time_t		o_time;		/* time op was initiated	  */
	char		*o_dn;		/* dn bound when op was initiated */
	int		o_authtype;	/* auth method used to bind dn	  */
					/* values taken from ldap.h	  */
					/* LDAP_AUTH_*			  */
	int		o_opid;		/* id of this operation		  */
	int		o_connid;	/* id of conn initiating this op  */
#ifdef CLDAP
	int		o_cldap;	/* != 0 if this came in via CLDAP */
	struct sockaddr	o_clientaddr;	/* client address if via CLDAP	  */
	char		o_searchbase;	/* search base if via CLDAP	  */
#endif
	struct op	*o_next;	/* next operation pending	  */
	pthread_t	o_tid;		/* thread handling this op	  */
	int		o_abandon;	/* signals op has been abandoned  */
	pthread_mutex_t	o_abandonmutex;	/* signals op has been abandoned  */

	int		o_private;	/* anything the backend needs	  */
} Operation;

/*
 * represents a connection from an ldap client
 */

typedef struct conn {
	Sockbuf		c_sb;		/* ber connection stuff		  */
	char		*c_dn;		/* current DN bound to this conn  */
	pthread_mutex_t	c_dnmutex;	/* mutex for c_dn field		  */
	int		c_authtype;	/* auth method used to bind c_dn  */
#ifdef COMPAT
	int		c_version;	/* for compatibility w/2.0, 3.0	  */
#endif
	char		*c_addr;	/* address of client on this conn */
	char		*c_domain;	/* domain of client on this conn  */
	Operation	*c_ops;		/* list of pending operations	  */
	pthread_mutex_t	c_opsmutex;	/* mutex for c_ops list & stats	  */
	pthread_mutex_t	c_pdumutex;	/* only one pdu written at a time */
	pthread_cond_t	c_wcv;		/* used to wait for sd write-ready*/
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

#ifdef NEEDPROTOS
#include "proto-slap.h"
#endif

#endif /* _slap_h_ */

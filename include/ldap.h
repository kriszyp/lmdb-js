/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LDAP_H
#define _LDAP_H

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

#define LDAP_PORT	389
#define LDAP_VERSION1	1
#define LDAP_VERSION2	2
#define LDAP_VERSION3	3
#define LDAP_VERSION		LDAP_VERSION2
#define LDAP_VERSION_MAX	LDAP_VERSION2

/*
 * We'll use 2000+draft revision for our API version number
 * As such, the number will be above the old RFC but below 
 * whatever number does finally get assigned
 */
#define LDAP_API_VERSION	2001
#define LDAP_VENDOR			"OpenLDAP"
/* We'll eventually release as 200 */
#define LDAP_VENDOR_VERSION	190

#define LDAP_COMPAT20
#define LDAP_COMPAT30
#if defined(LDAP_COMPAT20) || defined(LDAP_COMPAT30)
#define LDAP_COMPAT
#endif

#define LDAP_OPT_API_INFO			0x0000
#define LDAP_OPT_DESC				0x0001
#define LDAP_OPT_DEREF				0x0002
#define LDAP_OPT_SIZELIMIT			0x0003
#define LDAP_OPT_TIMELIMIT			0x0004
#define LDAP_OPT_REFERRALS			0x0008
#define LDAP_OPT_RESTART			0x0009
#define LDAP_OPT_PROTOCOL_VERSION	0x0011
#define LDAP_OPT_SERVER_CONTROLS	0x0012
#define LDAP_OPT_CLIENT_CONTROLS	0x0013
#define LDAP_OPT_HOST_NAME			0x0030
#define	LDAP_OPT_ERROR_NUMBER		0x0031
#define LDAP_OPT_ERROR_STRING		0x0032

/* for LDAPv2 compatibility */
#define LDAP_OPT_DNS				0x0101	/* use DN & DNS */

/* on/off values */
#define LDAP_OPT_ON		((void *) 1)
#define LDAP_OPT_OFF	((void *) 0)

#define LDAP_OPT_SUCCESS	0
#define	LDAP_OPT_ERROR		(-1)

extern int ldap_debug;

typedef struct ldapapiinfo {
	int		ldapai_info_version;		/* version of LDAPAPIInfo (1) */
	int		ldapai_api_version;			/* revision of API supported */
	int		ldapai_protocol_version;	/* highest LDAP version supported */
	char	**ldapai_extensions;		/* names of API extensions */
	char	*ldapai_vendor_name;		/* name of supplier */
	int		ldapai_vendor_version;		/* supplier-specific version times 100 */
} LDAPAPIInfo;

typedef struct ldapcontrol {
	char			*ldctl_oid;
	struct berval	ldctl_value;
	char			ldctl_iscritical;
} LDAPControl, *PLDAPControl;

#define LDAP_MAX_ATTR_LEN	100

/* 
 * specific LDAP instantiations of BER types we know about
 */

/* general stuff */
#define LDAP_TAG_MESSAGE	0x30L	/* tag is 16 + constructed bit */
#define OLD_LDAP_TAG_MESSAGE	0x10L	/* forgot the constructed bit  */
#define LDAP_TAG_MSGID		0x02L

/* possible operations a client can invoke */
#define LDAP_REQ_BIND			0x60L	/* application + constructed */
#define LDAP_REQ_UNBIND			0x42L	/* application + primitive   */
#define LDAP_REQ_SEARCH			0x63L	/* application + constructed */
#define LDAP_REQ_MODIFY			0x66L	/* application + constructed */
#define LDAP_REQ_ADD			0x68L	/* application + constructed */
#define LDAP_REQ_DELETE			0x4aL	/* application + primitive   */
#define LDAP_REQ_MODRDN			0x6cL	/* application + constructed */
#define LDAP_REQ_COMPARE		0x6eL	/* application + constructed */
#define LDAP_REQ_ABANDON		0x50L	/* application + primitive   */

/* version 3.0 compatibility stuff */
#define LDAP_REQ_UNBIND_30		0x62L
#define LDAP_REQ_DELETE_30		0x6aL
#define LDAP_REQ_ABANDON_30		0x70L

/* 
 * old broken stuff for backwards compatibility - forgot application tag
 * and constructed/primitive bit
 */
#define OLD_LDAP_REQ_BIND		0x00L
#define OLD_LDAP_REQ_UNBIND		0x02L
#define OLD_LDAP_REQ_SEARCH		0x03L
#define OLD_LDAP_REQ_MODIFY		0x06L
#define OLD_LDAP_REQ_ADD		0x08L
#define OLD_LDAP_REQ_DELETE		0x0aL
#define OLD_LDAP_REQ_MODRDN		0x0cL
#define OLD_LDAP_REQ_COMPARE		0x0eL
#define OLD_LDAP_REQ_ABANDON		0x10L

/* possible result types a server can return */
#define LDAP_RES_BIND			0x61L	/* application + constructed */
#define LDAP_RES_SEARCH_ENTRY		0x64L	/* application + constructed */
#define LDAP_RES_SEARCH_RESULT		0x65L	/* application + constructed */
#define LDAP_RES_MODIFY			0x67L	/* application + constructed */
#define LDAP_RES_ADD			0x69L	/* application + constructed */
#define LDAP_RES_DELETE			0x6bL	/* application + constructed */
#define LDAP_RES_MODRDN			0x6dL	/* application + constructed */
#define LDAP_RES_COMPARE		0x6fL	/* application + constructed */
#define LDAP_RES_ANY			(-1L)

/* old broken stuff for backwards compatibility */
#define OLD_LDAP_RES_BIND		0x01L
#define OLD_LDAP_RES_SEARCH_ENTRY	0x04L
#define OLD_LDAP_RES_SEARCH_RESULT	0x05L
#define OLD_LDAP_RES_MODIFY		0x07L
#define OLD_LDAP_RES_ADD		0x09L
#define OLD_LDAP_RES_DELETE		0x0bL
#define OLD_LDAP_RES_MODRDN		0x0dL
#define OLD_LDAP_RES_COMPARE		0x0fL

/* authentication methods available */
#define LDAP_AUTH_NONE		0x00L	/* no authentication		  */
#define LDAP_AUTH_SIMPLE	0x80L	/* context specific + primitive   */
#define LDAP_AUTH_KRBV4		0xffL	/* means do both of the following */
#define LDAP_AUTH_KRBV41	0x81L	/* context specific + primitive   */
#define LDAP_AUTH_KRBV42	0x82L	/* context specific + primitive   */

/* 3.0 compatibility auth methods */
#define LDAP_AUTH_SIMPLE_30	0xa0L	/* context specific + constructed */
#define LDAP_AUTH_KRBV41_30	0xa1L	/* context specific + constructed */
#define LDAP_AUTH_KRBV42_30	0xa2L	/* context specific + constructed */

/* old broken stuff */
#define OLD_LDAP_AUTH_SIMPLE	0x00L
#define OLD_LDAP_AUTH_KRBV4	0x01L
#define OLD_LDAP_AUTH_KRBV42	0x02L

/* filter types */
#define LDAP_FILTER_AND		0xa0L	/* context specific + constructed */
#define LDAP_FILTER_OR		0xa1L	/* context specific + constructed */
#define LDAP_FILTER_NOT		0xa2L	/* context specific + constructed */
#define LDAP_FILTER_EQUALITY	0xa3L	/* context specific + constructed */
#define LDAP_FILTER_SUBSTRINGS	0xa4L	/* context specific + constructed */
#define LDAP_FILTER_GE		0xa5L	/* context specific + constructed */
#define LDAP_FILTER_LE		0xa6L	/* context specific + constructed */
#define LDAP_FILTER_PRESENT	0x87L	/* context specific + primitive   */
#define LDAP_FILTER_APPROX	0xa8L	/* context specific + constructed */

/* 3.0 compatibility filter types */
#define LDAP_FILTER_PRESENT_30	0xa7L	/* context specific + constructed */

/* old broken stuff */
#define OLD_LDAP_FILTER_AND		0x00L
#define OLD_LDAP_FILTER_OR		0x01L
#define OLD_LDAP_FILTER_NOT		0x02L
#define OLD_LDAP_FILTER_EQUALITY	0x03L
#define OLD_LDAP_FILTER_SUBSTRINGS	0x04L
#define OLD_LDAP_FILTER_GE		0x05L
#define OLD_LDAP_FILTER_LE		0x06L
#define OLD_LDAP_FILTER_PRESENT		0x07L
#define OLD_LDAP_FILTER_APPROX		0x08L

/* substring filter component types */
#define LDAP_SUBSTRING_INITIAL	0x80L	/* context specific */
#define LDAP_SUBSTRING_ANY	0x81L	/* context specific */
#define LDAP_SUBSTRING_FINAL	0x82L	/* context specific */

/* 3.0 compatibility substring filter component types */
#define LDAP_SUBSTRING_INITIAL_30	0xa0L	/* context specific */
#define LDAP_SUBSTRING_ANY_30		0xa1L	/* context specific */
#define LDAP_SUBSTRING_FINAL_30		0xa2L	/* context specific */

/* old broken stuff */
#define OLD_LDAP_SUBSTRING_INITIAL	0x00L
#define OLD_LDAP_SUBSTRING_ANY		0x01L
#define OLD_LDAP_SUBSTRING_FINAL	0x02L

/* search scopes */
#define LDAP_SCOPE_BASE		0x00
#define LDAP_SCOPE_ONELEVEL	0x01
#define LDAP_SCOPE_SUBTREE	0x02

/* for modifications */
typedef struct ldapmod {
	int		mod_op;
#define LDAP_MOD_ADD		0x00
#define LDAP_MOD_DELETE		0x01
#define LDAP_MOD_REPLACE	0x02
#define LDAP_MOD_BVALUES	0x80
	char		*mod_type;
	union {
		char		**modv_strvals;
		struct berval	**modv_bvals;
	} mod_vals;
#define mod_values	mod_vals.modv_strvals
#define mod_bvalues	mod_vals.modv_bvals
	struct ldapmod	*mod_next;
} LDAPMod;

/* 
 * possible error codes we can return
 */

#define LDAP_SUCCESS			0x00
#define LDAP_OPERATIONS_ERROR		0x01
#define LDAP_PROTOCOL_ERROR		0x02
#define LDAP_TIMELIMIT_EXCEEDED		0x03
#define LDAP_SIZELIMIT_EXCEEDED		0x04
#define LDAP_COMPARE_FALSE		0x05
#define LDAP_COMPARE_TRUE		0x06
#define LDAP_STRONG_AUTH_NOT_SUPPORTED	0x07
#define LDAP_STRONG_AUTH_REQUIRED	0x08
#define LDAP_PARTIAL_RESULTS		0x09
#define	LDAP_REFERRAL		0x0a /* LDAPv3 */
#define LDAP_ADMINLIMIT_EXCEEDED	0x0b /* LDAPv3 */
#define	LDAP_UNAVAILABLE_CRITICIAL_EXTENSION	0x0c /* LDAPv3 */
#define LDAP_CONFIDENTIALITY_REQUIRED	0x0d /* LDAPv3 */
#define	LDAP_SASL_BIND_IN_PROGRESS	0x0e /* LDAPv3 */	

#define LDAP_NO_SUCH_ATTRIBUTE		0x10
#define LDAP_UNDEFINED_TYPE		0x11
#define LDAP_INAPPROPRIATE_MATCHING	0x12
#define LDAP_CONSTRAINT_VIOLATION	0x13
#define LDAP_TYPE_OR_VALUE_EXISTS	0x14
#define LDAP_INVALID_SYNTAX		0x15

#define LDAP_NO_SUCH_OBJECT		0x20
#define LDAP_ALIAS_PROBLEM		0x21
#define LDAP_INVALID_DN_SYNTAX		0x22
#define LDAP_IS_LEAF			0x23 /* not LDAPv3 */
#define LDAP_ALIAS_DEREF_PROBLEM	0x24

#define NAME_ERROR(n)	((n & 0xf0) == 0x20)

#define LDAP_INAPPROPRIATE_AUTH		0x30
#define LDAP_INVALID_CREDENTIALS	0x31
#define LDAP_INSUFFICIENT_ACCESS	0x32
#define LDAP_BUSY			0x33
#define LDAP_UNAVAILABLE		0x34
#define LDAP_UNWILLING_TO_PERFORM	0x35
#define LDAP_LOOP_DETECT		0x36

#define LDAP_NAMING_VIOLATION		0x40
#define LDAP_OBJECT_CLASS_VIOLATION	0x41
#define LDAP_NOT_ALLOWED_ON_NONLEAF	0x42
#define LDAP_NOT_ALLOWED_ON_RDN		0x43
#define LDAP_ALREADY_EXISTS		0x44
#define LDAP_NO_OBJECT_CLASS_MODS	0x45
#define LDAP_RESULTS_TOO_LARGE		0x46 /* CLDAP */
#define LDAP_AFFECTS_MULTIPLE_DSAS	0x47 /* LDAPv3 */

#define LDAP_OTHER			0x50
#define LDAP_SERVER_DOWN		0x51
#define LDAP_LOCAL_ERROR		0x52
#define LDAP_ENCODING_ERROR		0x53
#define LDAP_DECODING_ERROR		0x54
#define LDAP_TIMEOUT			0x55
#define LDAP_AUTH_UNKNOWN		0x56
#define LDAP_FILTER_ERROR		0x57
#define LDAP_USER_CANCELLED		0x58
#define LDAP_PARAM_ERROR		0x59
#define LDAP_NO_MEMORY			0x5a


/* default limit on nesting of referrals */
#define LDAP_DEFAULT_REFHOPLIMIT	5

/*
 * This structure represents both ldap messages and ldap responses.
 * These are really the same, except in the case of search responses,
 * where a response has multiple messages.
 */

typedef struct ldapmsg LDAPMessage;
#define NULLMSG	((LDAPMessage *) NULL)


#ifdef LDAP_REFERRALS
/*
 * structure for tracking LDAP server host, ports, DNs, etc.
 */
typedef struct ldap_server {
	char			*lsrv_host;
	char			*lsrv_dn;	/* if NULL, use default */
	int			lsrv_port;
	struct ldap_server	*lsrv_next;
} LDAPServer;


/*
 * structure for representing an LDAP server connection
 */
typedef struct ldap_conn {
	Sockbuf			*lconn_sb;
	int			lconn_refcnt;
	time_t		lconn_lastused;	/* time */
	int			lconn_status;
#define LDAP_CONNST_NEEDSOCKET		1
#define LDAP_CONNST_CONNECTING		2
#define LDAP_CONNST_CONNECTED		3
	LDAPServer		*lconn_server;
	char			*lconn_krbinstance;
	struct ldap_conn	*lconn_next;
} LDAPConn;


/*
 * structure used to track outstanding requests
 */
typedef struct ldapreq {
	int		lr_msgid;	/* the message id */
	int		lr_status;	/* status of request */
#define LDAP_REQST_INPROGRESS	1
#define LDAP_REQST_CHASINGREFS	2
#define LDAP_REQST_NOTCONNECTED	3
#define LDAP_REQST_WRITING	4
	int		lr_outrefcnt;	/* count of outstanding referrals */
	int		lr_origid;	/* original request's message id */
	int		lr_parentcnt;	/* count of parent requests */
	int		lr_res_msgtype;	/* result message type */
	int		lr_res_errno;	/* result LDAP errno */
	char		*lr_res_error;	/* result error string */
	char		*lr_res_matched;/* result matched DN string */
	BerElement	*lr_ber;	/* ber encoded request contents */
	LDAPConn	*lr_conn;	/* connection used to send request */
	struct ldapreq	*lr_parent;	/* request that spawned this referral */
	struct ldapreq	*lr_refnext;	/* next referral spawned */
	struct ldapreq	*lr_prev;	/* previous request */
	struct ldapreq	*lr_next;	/* next request */
} LDAPRequest;
#endif /* LDAP_REFERRALS */


/*
 * structure for client cache
 */
#define LDAP_CACHE_BUCKETS	31	/* cache hash table size */
typedef struct ldapcache {
	LDAPMessage	*lc_buckets[LDAP_CACHE_BUCKETS];/* hash table */
	LDAPMessage	*lc_requests;			/* unfulfilled reqs */
	long		lc_timeout;			/* request timeout */
	long		lc_maxmem;			/* memory to use */
	long		lc_memused;			/* memory in use */
	int		lc_enabled;			/* enabled? */
	unsigned long	lc_options;			/* options */
#define LDAP_CACHE_OPT_CACHENOERRS	0x00000001
#define LDAP_CACHE_OPT_CACHEALLERRS	0x00000002
}  LDAPCache;
#define NULLLDCACHE ((LDAPCache *)NULL)

/*
 * structures for ldap getfilter routines
 */

typedef struct ldap_filt_info {
	char			*lfi_filter;
	char			*lfi_desc;
	int			lfi_scope;	/* LDAP_SCOPE_BASE, etc */
	int			lfi_isexact;	/* exact match filter? */
	struct ldap_filt_info	*lfi_next;
} LDAPFiltInfo;

typedef struct ldap_filt_list {
    char			*lfl_tag;
    char			*lfl_pattern;
    char			*lfl_delims;
    LDAPFiltInfo		*lfl_ilist;
    struct ldap_filt_list	*lfl_next;
} LDAPFiltList;


#define LDAP_FILT_MAXSIZ	1024

typedef struct ldap_filt_desc {
	LDAPFiltList		*lfd_filtlist;
	LDAPFiltInfo		*lfd_curfip;
	LDAPFiltInfo		lfd_retfi;
	char			lfd_filter[ LDAP_FILT_MAXSIZ ];
	char			*lfd_curval;
	char			*lfd_curvalcopy;
	char			**lfd_curvalwords;
	char			*lfd_filtprefix;
	char			*lfd_filtsuffix;
} LDAPFiltDesc;


/*
 * structure representing an ldap connection
 */

typedef struct ldap LDAP;

#define LDAP_DEREF_NEVER	0x00
#define LDAP_DEREF_SEARCHING	0x01
#define LDAP_DEREF_FINDING	0x02
#define LDAP_DEREF_ALWAYS	0x03

#define LDAP_NO_LIMIT		0


/*
 * structure for ldap friendly mapping routines
 */

typedef struct friendly {
	char	*f_unfriendly;
	char	*f_friendly;
} FriendlyMap;


/*
 * handy macro to check whether LDAP struct is set up for CLDAP or not
 */
#define LDAP_IS_CLDAP( ld )	( (ld)->ld_sb.sb_naddr > 0 )


/*
 * types for ldap URL handling
 */
typedef struct ldap_url_desc {
    char	*lud_host;
    int		lud_port;
    char	*lud_dn;
    char	**lud_attrs;
    int		lud_scope;
    char	*lud_filter;
    char	*lud_string;	/* for internal use only */
} LDAPURLDesc;
#define NULLLDAPURLDESC	((LDAPURLDesc *)NULL)

#define LDAP_URL_ERR_NOTLDAP	1	/* URL doesn't begin with "ldap://" */
#define LDAP_URL_ERR_NODN	2	/* URL has no DN (required) */
#define LDAP_URL_ERR_BADSCOPE	3	/* URL scope string is invalid */
#define LDAP_URL_ERR_MEM	4	/* can't allocate memory space */

/* avoid pulling in headers */
struct timeval;

LDAP_F int ldap_get_option LDAP_P((LDAP *ld, int option, void *outvalue));
LDAP_F int ldap_set_option LDAP_P((LDAP *ld, int option, void *invalue));

LDAP_F void ldap_control_free LDAP_P(( LDAPControl *ctrl ));
LDAP_F void ldap_controls_free LDAP_P(( LDAPControl **ctrls ));
  
/*
 * in abandon.c:
 */
LDAP_F int ldap_abandon LDAP_P(( LDAP *ld, int msgid ));

/*
 * in add.c:
 */
LDAP_F int ldap_add LDAP_P(( LDAP *ld, char *dn, LDAPMod **attrs ));
LDAP_F int ldap_add_s LDAP_P(( LDAP *ld, char *dn, LDAPMod **attrs ));

/*
 * in bind.c:
 */
LDAP_F int ldap_bind LDAP_P(( LDAP *ld, char *who, char *passwd, int authmethod ));
LDAP_F int ldap_bind_s LDAP_P(( LDAP *ld, char *who, char *cred, int method ));
LDAP_F void ldap_set_rebind_proc LDAP_P(( LDAP *ld,
	int (*rebindproc) LDAP_P(( LDAP *ld, char **dnp, char **passwdp, int *authmethodp, int freeit ))
));

/*
 * in sbind.c:
 */
LDAP_F int ldap_simple_bind LDAP_P(( LDAP *ld, char *who, char *passwd ));
LDAP_F int ldap_simple_bind_s LDAP_P(( LDAP *ld, char *who, char *passwd ));

/*
 * in kbind.c:
 */
LDAP_F int ldap_kerberos_bind_s LDAP_P(( LDAP *ld, char *who ));
LDAP_F int ldap_kerberos_bind1 LDAP_P(( LDAP *ld, char *who ));
LDAP_F int ldap_kerberos_bind1_s LDAP_P(( LDAP *ld, char *who ));
LDAP_F int ldap_kerberos_bind2 LDAP_P(( LDAP *ld, char *who ));
LDAP_F int ldap_kerberos_bind2_s LDAP_P(( LDAP *ld, char *who ));
 

/*
 * in cache.c
 */
LDAP_F int ldap_enable_cache LDAP_P(( LDAP *ld, long timeout, long maxmem ));
LDAP_F void ldap_disable_cache LDAP_P(( LDAP *ld ));
LDAP_F void ldap_set_cache_options LDAP_P(( LDAP *ld, unsigned long opts ));
LDAP_F void ldap_destroy_cache LDAP_P(( LDAP *ld ));
LDAP_F void ldap_flush_cache LDAP_P(( LDAP *ld ));
LDAP_F void ldap_uncache_entry LDAP_P(( LDAP *ld, char *dn ));
LDAP_F void ldap_uncache_request LDAP_P(( LDAP *ld, int msgid ));

/*
 * in compare.c:
 */
LDAP_F int ldap_compare LDAP_P(( LDAP *ld, char *dn, char *attr, char *value ));
LDAP_F int ldap_compare_s LDAP_P(( LDAP *ld, char *dn, char *attr, char *value ));

/*
 * in delete.c:
 */
LDAP_F int ldap_delete LDAP_P(( LDAP *ld, char *dn ));
LDAP_F int ldap_delete_s LDAP_P(( LDAP *ld, char *dn ));

/*
 * in error.c:
 */
LDAP_F int ldap_result2error LDAP_P(( LDAP *ld, LDAPMessage *r, int freeit ));
LDAP_F char *ldap_err2string LDAP_P(( int err ));
LDAP_F void ldap_perror LDAP_P(( LDAP *ld, char *s ));
LDAP_F int ldap_get_lderrno LDAP_P((LDAP *ld, char **matched, char **msg));

/*
 * in modify.c:
 */
LDAP_F int ldap_modify LDAP_P(( LDAP *ld, char *dn, LDAPMod **mods ));
LDAP_F int ldap_modify_s LDAP_P(( LDAP *ld, char *dn, LDAPMod **mods ));

/*
 * in modrdn.c:
 */
LDAP_F int ldap_modrdn LDAP_P(( LDAP *ld, char *dn, char *newrdn ));
LDAP_F int ldap_modrdn_s LDAP_P(( LDAP *ld, char *dn, char *newrdn ));
LDAP_F int ldap_modrdn2 LDAP_P(( LDAP *ld, char *dn, char *newrdn,
	int deleteoldrdn ));
LDAP_F int ldap_modrdn2_s LDAP_P(( LDAP *ld, char *dn, char *newrdn,
	int deleteoldrdn));

/*
 * in open.c:
 */
LDAP_F LDAP *ldap_open LDAP_P(( char *host, int port ));
LDAP_F LDAP *ldap_init LDAP_P(( char *defhost, int defport ));

/*
 * in getentry.c:
 */
LDAP_F LDAPMessage *ldap_first_entry LDAP_P(( LDAP *ld, LDAPMessage *chain ));
LDAP_F LDAPMessage *ldap_next_entry LDAP_P(( LDAP *ld, LDAPMessage *entry ));
LDAP_F int ldap_count_entries LDAP_P(( LDAP *ld, LDAPMessage *chain ));

/*
 * in addentry.c
 */
LDAP_F LDAPMessage *ldap_delete_result_entry LDAP_P(( LDAPMessage **list,
	LDAPMessage *e ));
LDAP_F void ldap_add_result_entry LDAP_P(( LDAPMessage **list, LDAPMessage *e ));

/*
 * in getdn.c
 */
LDAP_F char *ldap_get_dn LDAP_P(( LDAP *ld, LDAPMessage *entry ));
LDAP_F char *ldap_dn2ufn LDAP_P(( char *dn ));
LDAP_F char **ldap_explode_dn LDAP_P(( char *dn, int notypes ));
LDAP_F char **ldap_explode_dns LDAP_P(( char *dn ));
LDAP_F int ldap_is_dns_dn LDAP_P(( char *dn ));

/*
 * in getattr.c
 */
LDAP_F char *ldap_first_attribute LDAP_P(( LDAP *ld, LDAPMessage *entry,
	BerElement **ber ));
LDAP_F char *ldap_next_attribute LDAP_P(( LDAP *ld, LDAPMessage *entry,
	BerElement *ber ));

/*
 * in getvalues.c
 */
LDAP_F char **ldap_get_values LDAP_P(( LDAP *ld, LDAPMessage *entry, char *target ));
LDAP_F struct berval **ldap_get_values_len LDAP_P(( LDAP *ld, LDAPMessage *entry,
	char *target ));
LDAP_F int ldap_count_values LDAP_P(( char **vals ));
LDAP_F int ldap_count_values_len LDAP_P(( struct berval **vals ));
LDAP_F void ldap_value_free LDAP_P(( char **vals ));
LDAP_F void ldap_value_free_len LDAP_P(( struct berval **vals ));

/*
 * in result.c:
 */
LDAP_F int ldap_result LDAP_P(( LDAP *ld, int msgid, int all,
	struct timeval *timeout, LDAPMessage **result ));
LDAP_F int ldap_msgfree LDAP_P(( LDAPMessage *lm ));
LDAP_F int ldap_msgdelete LDAP_P(( LDAP *ld, int msgid ));

/*
 * in search.c:
 */
LDAP_F int ldap_search LDAP_P(( LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly ));
LDAP_F int ldap_search_s LDAP_P(( LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPMessage **res ));
LDAP_F int ldap_search_st LDAP_P(( LDAP *ld, char *base, int scope, char *filter,
    char **attrs, int attrsonly, struct timeval *timeout, LDAPMessage **res ));

/*
 * in ufn.c
 */
LDAP_F int ldap_ufn_search_c LDAP_P(( LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res, int (*cancelproc)( void *cl ),
	void *cancelparm ));
LDAP_F int ldap_ufn_search_ct LDAP_P(( LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res, int (*cancelproc)( void *cl ),
	void *cancelparm, char *tag1, char *tag2, char *tag3 ));
LDAP_F int ldap_ufn_search_s LDAP_P(( LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res ));
LDAP_F LDAPFiltDesc *ldap_ufn_setfilter LDAP_P(( LDAP *ld, char *fname ));
LDAP_F void ldap_ufn_setprefix LDAP_P(( LDAP *ld, char *prefix ));
LDAP_F int ldap_ufn_timeout LDAP_P(( void *tvparam ));


/*
 * in unbind.c
 */
LDAP_F int ldap_unbind LDAP_P(( LDAP *ld ));
LDAP_F int ldap_unbind_s LDAP_P(( LDAP *ld ));


/*
 * in getfilter.c
 */
LDAP_F LDAPFiltDesc *ldap_init_getfilter LDAP_P(( char *fname ));
LDAP_F LDAPFiltDesc *ldap_init_getfilter_buf LDAP_P(( char *buf, long buflen ));
LDAP_F LDAPFiltInfo *ldap_getfirstfilter LDAP_P(( LDAPFiltDesc *lfdp, char *tagpat,
	char *value ));
LDAP_F LDAPFiltInfo *ldap_getnextfilter LDAP_P(( LDAPFiltDesc *lfdp ));
LDAP_F void ldap_setfilteraffixes LDAP_P(( LDAPFiltDesc *lfdp, char *prefix, char *suffix ));
LDAP_F void ldap_build_filter LDAP_P(( char *buf, unsigned long buflen,
	char *pattern, char *prefix, char *suffix, char *attr,
	char *value, char **valwords ));

/*
 * in free.c
 */
LDAP_F void ldap_getfilter_free LDAP_P(( LDAPFiltDesc *lfdp ));
LDAP_F void ldap_mods_free LDAP_P(( LDAPMod **mods, int freemods ));

/*
 * in friendly.c
 */
LDAP_F char *ldap_friendly_name LDAP_P(( char *filename, char *uname,
	FriendlyMap **map ));
LDAP_F void ldap_free_friendlymap LDAP_P(( FriendlyMap **map ));


/*
 * in cldap.c
 */
LDAP_F LDAP *cldap_open LDAP_P(( char *host, int port ));
LDAP_F void cldap_close LDAP_P(( LDAP *ld ));
LDAP_F int cldap_search_s LDAP_P(( LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPMessage **res, char *logdn ));
LDAP_F void cldap_setretryinfo LDAP_P(( LDAP *ld, int tries, int timeout ));


/*
 * in sort.c
 */
LDAP_F int ldap_sort_entries LDAP_P(( LDAP *ld,
	LDAPMessage **chain, char *attr, int (*cmp) () ));
LDAP_F int ldap_sort_values LDAP_P(( LDAP *ld,
	char **vals, int (*cmp) LDAP_P((const void *, const void *)) ));
LDAP_F int ldap_sort_strcasecmp LDAP_P(( char **a, char **b ));


/*
 * in url.c
 */
LDAP_F int ldap_is_ldap_url LDAP_P(( char *url ));
LDAP_F int ldap_url_parse LDAP_P(( char *url, LDAPURLDesc **ludpp ));
LDAP_F void ldap_free_urldesc LDAP_P(( LDAPURLDesc *ludp ));
LDAP_F int ldap_url_search LDAP_P(( LDAP *ld, char *url, int attrsonly ));
LDAP_F int ldap_url_search_s LDAP_P(( LDAP *ld, char *url, int attrsonly,
	LDAPMessage **res ));
LDAP_F int ldap_url_search_st LDAP_P(( LDAP *ld, char *url, int attrsonly,
	struct timeval *timeout, LDAPMessage **res ));


/*
 * in charset.c
 */
LDAP_F void ldap_set_string_translators LDAP_P(( LDAP *ld,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc ));
LDAP_F int ldap_translate_from_t61 LDAP_P(( LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input ));
LDAP_F int ldap_translate_to_t61 LDAP_P(( LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input ));
LDAP_F void ldap_enable_translation LDAP_P(( LDAP *ld, LDAPMessage *entry,
	int enable ));

LDAP_F int ldap_t61_to_8859 LDAP_P(( char **bufp, unsigned long *buflenp,
	int free_input ));
LDAP_F int ldap_8859_to_t61 LDAP_P(( char **bufp, unsigned long *buflenp,
	int free_input ));


/*
 * in msdos/winsock/wsa.c
 */
LDAP_F void ldap_memfree LDAP_P(( void *p ));

LDAP_END_DECL

#endif /* _LDAP_H */

/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  ldap-int.h - defines & prototypes internal to the LDAP library
 */

#ifndef	_LDAP_INT_H
#define	_LDAP_INT_H 1

#include "../liblber/lber-int.h"
#include "ldap_log.h"
#include "ldap.h"

LDAP_BEGIN_DECL

#define LDAP_URL_PREFIX         "ldap://"
#define LDAP_URL_PREFIX_LEN     7
#define LDAP_URL_URLCOLON	"URL:"
#define LDAP_URL_URLCOLON_LEN	4

#ifdef LDAP_REFERRALS
#define LDAP_REF_STR		"Referral:\n"
#define LDAP_REF_STR_LEN	10
#define LDAP_LDAP_REF_STR	LDAP_URL_PREFIX
#define LDAP_LDAP_REF_STR_LEN	LDAP_URL_PREFIX_LEN
#ifdef LDAP_DNS
#define LDAP_DX_REF_STR		"dx://"
#define LDAP_DX_REF_STR_LEN	5
#endif /* LDAP_DNS */
#endif /* LDAP_REFERRALS */

#define LDAP_BOOL_REFERRALS		0
#define LDAP_BOOL_RESTART		1
#define LDAP_BOOL_DNS			2

#define LDAP_BOOL(n)	(1 << (n))
#define LDAP_BOOL_GET(ld, bool)	((ld)->ld_booleans & LDAP_BOOL(bool) \
									?  LDAP_OPT_ON : LDAP_OPT_OFF)
#define LDAP_BOOL_SET(ld, bool) ((ld)->ld_booleans |= LDAP_BOOL(bool))
#define LDAP_BOOL_CLR(ld, bool) ((ld)->ld_booleans &= ~LDAP_BOOL(bool))
#define LDAP_BOOL_ZERO(ld) ((ld)->ld_booleans = 0)

/*
 * This structure represents both ldap messages and ldap responses.
 * These are really the same, except in the case of search responses,
 * where a response has multiple messages.
 */

struct ldapmsg {
	int		lm_msgid;	/* the message id */
	int		lm_msgtype;	/* the message type */
	BerElement	*lm_ber;	/* the ber encoded message contents */
	struct ldapmsg	*lm_chain;	/* for search - next msg in the resp */
	struct ldapmsg	*lm_next;	/* next response */
	unsigned int	lm_time;	/* used to maintain cache */
};

/*
 * structure representing an ldap connection
 */

struct ldap {
	Sockbuf		ld_sb;		/* socket descriptor & buffer */
	char		*ld_host;
	int		ld_version;
	char		ld_lberoptions;
	int		ld_deref;
	int		ld_timelimit;
	int		ld_sizelimit;

	LDAPFiltDesc	*ld_filtd;	/* from getfilter for ufn searches */
	char		*ld_ufnprefix;	/* for incomplete ufn's */

	int		ld_errno;
	char		*ld_error;
	char		*ld_matched;
	int		ld_msgid;

	/* do not mess with these */
#ifdef LDAP_REFERRALS
	LDAPRequest	*ld_requests;	/* list of outstanding requests */
#else /* LDAP_REFERRALS */
	LDAPMessage	*ld_requests;	/* list of outstanding requests */
#endif /* LDAP_REFERRALS */
	LDAPMessage	*ld_responses;	/* list of outstanding responses */
	int		*ld_abandoned;	/* array of abandoned requests */
	char		ld_attrbuffer[LDAP_MAX_ATTR_LEN];
	LDAPCache	*ld_cache;	/* non-null if cache is initialized */
	char		*ld_cldapdn;	/* DN used in connectionless search */

	/* it is OK to change these next four values directly */
	int		ld_cldaptries;	/* connectionless search retry count */
	int		ld_cldaptimeout;/* time between retries */
	int		ld_refhoplimit;	/* limit on referral nesting */
	unsigned long	ld_booleans;	/* boolean options */

	/* do not mess with the rest though */
	char		*ld_defhost;	/* full name of default server */
	int		ld_defport;	/* port of default server */
	BERTranslateProc ld_lber_encode_translate_proc;
	BERTranslateProc ld_lber_decode_translate_proc;
#ifdef LDAP_REFERRALS
	LDAPConn	*ld_defconn;	/* default connection */
	LDAPConn	*ld_conns;	/* list of server connections */
	void		*ld_selectinfo;	/* platform specifics for select */
	int		(*ld_rebindproc)( struct ldap *ld, char **dnp,
				char **passwdp, int *authmethodp, int freeit );
				/* routine to get info needed for re-bind */
#endif /* LDAP_REFERRALS */
};


/*
 * in init.c
 */
extern int openldap_ldap_initialized;
extern struct ldap openldap_ld_globals;
void openldap_ldap_initialize LDAP_P((void));

/*
 * in cache.c
 */
void ldap_add_request_to_cache LDAP_P(( LDAP *ld, unsigned long msgtype,
        BerElement *request ));
void ldap_add_result_to_cache LDAP_P(( LDAP *ld, LDAPMessage *result ));
int ldap_check_cache LDAP_P(( LDAP *ld, unsigned long msgtype, BerElement *request ));


#ifdef HAVE_KERBEROS
/*
 * in kerberos.c
 */
char *ldap_get_kerberosv4_credentials LDAP_P(( LDAP *ld, char *who, char *service,
        int *len ));

#endif /* HAVE_KERBEROS */


/*
 * in open.c
 */
int open_ldap_connection( LDAP *ld, Sockbuf *sb, char *host, int defport,
	char **krbinstancep, int async );


/*
 * in os-ip.c
 */
int ldap_connect_to_host( Sockbuf *sb, char *host, unsigned long address, int port,
	int async );
void ldap_close_connection( Sockbuf *sb );

#ifdef HAVE_KERBEROS
char *ldap_host_connected_to( Sockbuf *sb );
#endif /* HAVE_KERBEROS */

#ifdef LDAP_REFERRALS
int do_ldap_select( LDAP *ld, struct timeval *timeout );
void *ldap_new_select_info( void );
void ldap_free_select_info( void *sip );
void ldap_mark_select_write( LDAP *ld, Sockbuf *sb );
void ldap_mark_select_read( LDAP *ld, Sockbuf *sb );
void ldap_mark_select_clear( LDAP *ld, Sockbuf *sb );
int ldap_is_read_ready( LDAP *ld, Sockbuf *sb );
int ldap_is_write_ready( LDAP *ld, Sockbuf *sb );
#endif /* LDAP_REFERRALS */


/*
 * in request.c
 */
int ldap_send_initial_request( LDAP *ld, unsigned long msgtype,
	char *dn, BerElement *ber );
BerElement *ldap_alloc_ber_with_options( LDAP *ld );
void ldap_set_ber_options( LDAP *ld, BerElement *ber );

#if defined( LDAP_REFERRALS ) || defined( LDAP_DNS )
int ldap_send_server_request( LDAP *ld, BerElement *ber, int msgid,
	LDAPRequest *parentreq, LDAPServer *srvlist, LDAPConn *lc,
	int bind );
LDAPConn *ldap_new_connection( LDAP *ld, LDAPServer **srvlistp, int use_ldsb,
	int connect, int bind );
LDAPRequest *ldap_find_request_by_msgid( LDAP *ld, int msgid );
void ldap_free_request( LDAP *ld, LDAPRequest *lr );
void ldap_free_connection( LDAP *ld, LDAPConn *lc, int force, int unbind );
void ldap_dump_connection( LDAP *ld, LDAPConn *lconns, int all );
void ldap_dump_requests_and_responses( LDAP *ld );
#endif /* LDAP_REFERRALS || LDAP_DNS */

#ifdef LDAP_REFERRALS
int ldap_chase_referrals( LDAP *ld, LDAPRequest *lr, char **errstrp, int *hadrefp );
int ldap_append_referral( LDAP *ld, char **referralsp, char *s );
#endif /* LDAP_REFERRALS */


/*
 * in search.c
 */
BerElement *ldap_build_search_req( LDAP *ld, char *base, int scope,
	char *filter, char **attrs, int attrsonly );


/*
 * in unbind.c
 */
int ldap_ld_free( LDAP *ld, int close );
int ldap_send_unbind( LDAP *ld, Sockbuf *sb );

#ifdef LDAP_DNS
/*
 * in getdxbyname.c
 */
char **ldap_getdxbyname( char *domain );
#endif /* LDAP_DNS */

#if defined( STR_TRANSLATION ) && defined( LDAP_DEFAULT_CHARSET )
/*
 * in charset.c
 *
 * added-in this stuff so that libldap.a would build, i.e. refs to 
 * these routines from open.c would resolve. 
 * hodges@stanford.edu 5-Feb-96
 */
#if LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET
extern 
int ldap_t61_to_8859( char **bufp, unsigned long *buflenp, int free_input );
extern 
int ldap_8859_to_t61( char **bufp, unsigned long *buflenp, int free_input );
#endif /* LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET */

LDAP_END_DECL
#endif /* STR_TRANSLATION && LDAP_DEFAULT_CHARSET */

#endif /* _LDAP_INT_H */

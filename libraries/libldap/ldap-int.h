/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  ldap-int.h - defines & prototypes internal to the LDAP library
 */


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


/*
 * in cache.c
 */
void ldap_add_request_to_cache LDAP_P(( LDAP *ld, unsigned long msgtype,
        BerElement *request ));
void ldap_add_result_to_cache LDAP_P(( LDAP *ld, LDAPMessage *result ));
int ldap_check_cache LDAP_P(( LDAP *ld, unsigned long msgtype, BerElement *request ));


#ifdef KERBEROS
/*
 * in kerberos.c
 */
char *ldap_get_kerberosv4_credentials LDAP_P(( LDAP *ld, char *who, char *service,
        int *len ));

#endif /* KERBEROS */


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

#ifdef KERBEROS
char *ldap_host_connected_to( Sockbuf *sb );
#endif /* KERBEROS */

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
#endif /* STR_TRANSLATION && LDAP_DEFAULT_CHARSET */

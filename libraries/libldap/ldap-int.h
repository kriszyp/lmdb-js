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
#ifdef NEEDPROTOS
void ldap_add_request_to_cache( LDAP *ld, unsigned long msgtype,
        BerElement *request );
void ldap_add_result_to_cache( LDAP *ld, LDAPMessage *result );
int ldap_check_cache( LDAP *ld, unsigned long msgtype, BerElement *request );
#else /* NEEDPROTOS */
void ldap_add_request_to_cache();
void ldap_add_result_to_cache();
int ldap_check_cache();
#endif /* NEEDPROTOS */


#ifdef KERBEROS
/*
 * in kerberos.c
 */
#ifdef NEEDPROTOS
char *ldap_get_kerberosv4_credentials( LDAP *ld, char *who, char *service,
        int *len );
#else /* NEEDPROTOS */
char *ldap_get_kerberosv4_credentials();
#endif /* NEEDPROTOS */

#endif /* KERBEROS */


/*
 * in open.c
 */
#ifdef NEEDPROTOS
int open_ldap_connection( LDAP *ld, Sockbuf *sb, char *host, int defport,
	char **krbinstancep, int async );
#else /* NEEDPROTOS */
int open_ldap_connection();
#endif /* NEEDPROTOS */


/*
 * in os-ip.c
 */
#ifdef NEEDPROTOS
int ldap_connect_to_host( Sockbuf *sb, char *host, unsigned long address, int port,
	int async );
void ldap_close_connection( Sockbuf *sb );
#else /* NEEDPROTOS */
int ldap_connect_to_host();
void ldap_close_connection();
#endif /* NEEDPROTOS */

#ifdef KERBEROS
#ifdef NEEDPROTOS
char *ldap_host_connected_to( Sockbuf *sb );
#else /* NEEDPROTOS */
char *host_connected_to();
#endif /* NEEDPROTOS */
#endif /* KERBEROS */

#ifdef LDAP_REFERRALS
#ifdef NEEDPROTOS
int do_ldap_select( LDAP *ld, struct timeval *timeout );
void *ldap_new_select_info( void );
void ldap_free_select_info( void *sip );
void ldap_mark_select_write( LDAP *ld, Sockbuf *sb );
void ldap_mark_select_read( LDAP *ld, Sockbuf *sb );
void ldap_mark_select_clear( LDAP *ld, Sockbuf *sb );
int ldap_is_read_ready( LDAP *ld, Sockbuf *sb );
int ldap_is_write_ready( LDAP *ld, Sockbuf *sb );
#else /* NEEDPROTOS */
int do_ldap_select();
void *ldap_new_select_info();
void ldap_free_select_info();
void ldap_mark_select_write();
void ldap_mark_select_read();
void ldap_mark_select_clear();
int ldap_is_read_ready();
int ldap_is_write_ready();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS */


/*
 * in request.c
 */
#ifdef NEEDPROTOS
int ldap_send_initial_request( LDAP *ld, unsigned long msgtype,
	char *dn, BerElement *ber );
BerElement *ldap_alloc_ber_with_options( LDAP *ld );
void ldap_set_ber_options( LDAP *ld, BerElement *ber );
#else /* NEEDPROTOS */
int ldap_send_initial_request();
BerElement *ldap_alloc_ber_with_options();
void ldap_set_ber_options();
#endif /* NEEDPROTOS */

#if defined( LDAP_REFERRALS ) || defined( LDAP_DNS )
#ifdef NEEDPROTOS
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
#else /* NEEDPROTOS */
int ldap_send_server_request();
LDAPConn *ldap_new_connection();
LDAPRequest *ldap_find_request_by_msgid();
void ldap_free_request();
void ldap_free_connection();
void ldap_dump_connection();
void ldap_dump_requests_and_responses();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS || LDAP_DNS */

#ifdef LDAP_REFERRALS
#ifdef NEEDPROTOS
int ldap_chase_referrals( LDAP *ld, LDAPRequest *lr, char **errstrp, int *hadrefp );
int ldap_append_referral( LDAP *ld, char **referralsp, char *s );
#else /* NEEDPROTOS */
int ldap_chase_referrals();
int ldap_append_referral();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS */


/*
 * in search.c
 */
#ifdef NEEDPROTOS
BerElement *ldap_build_search_req( LDAP *ld, char *base, int scope,
	char *filter, char **attrs, int attrsonly );
#else /* NEEDPROTOS */
BerElement *ldap_build_search_req();
#endif /* NEEDPROTOS */


/*
 * in unbind.c
 */
#ifdef NEEDPROTOS
int ldap_ld_free( LDAP *ld, int close );
int ldap_send_unbind( LDAP *ld, Sockbuf *sb );
#else /* NEEDPROTOS */
int ldap_ld_free();
int ldap_send_unbind();
#endif /* NEEDPROTOS */


#ifdef LDAP_DNS
/*
 * in getdxbyname.c
 */
#ifdef NEEDPROTOS
char **ldap_getdxbyname( char *domain );
#else /* NEEDPROTOS */
char **ldap_getdxbyname();
#endif /* NEEDPROTOS */
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
#ifdef NEEDPROTOS
extern 
int ldap_t61_to_8859( char **bufp, unsigned long *buflenp, int free_input );
extern 
int ldap_8859_to_t61( char **bufp, unsigned long *buflenp, int free_input );
#else /* NEEDPROTOS */
extern
int ldap_t61_to_8859();
extern
int ldap_8859_to_t61();
#endif /* NEEDPROTOS */
#endif /* LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET */
#endif /* STR_TRANSLATION && LDAP_DEFAULT_CHARSET */

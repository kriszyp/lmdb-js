#ifndef _PROTO_LDAPD_H
#define _PROTO_LDAPD_H

#include <ldap_cdefs.h>

/*
 * abandon.c
 */

int do_abandon LDAP_P(( struct conn *dsaconn, BerElement *ber, int msgid ));

/*
 * add.c
 */

int do_add LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
void add_result LDAP_P(( Sockbuf *sb, struct msg *m ));

/*
 * association.c
 */

struct conn *conn_dup LDAP_P(( struct conn *cn ));
int conn_init LDAP_P(( void ));
void conn_free LDAP_P(( struct conn *conn ));
void conn_del LDAP_P(( struct conn *conn ));
void conn_setfds LDAP_P(( fd_set *fds ));
void conn_badfds LDAP_P(( void ));
struct conn *conn_getfd LDAP_P(( fd_set *fds ));
void conn_add LDAP_P(( struct conn *new ));
struct conn *conn_find LDAP_P(( struct conn *c ));
void conn_close LDAP_P(( void ));
int isclosed LDAP_P(( int ad ));

/*
 * bind.c
 */

int do_bind LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber, int *bound ));
int do_bind_real LDAP_P(( struct conn *dsaconn, int *bound, char **matched ));

/*
 * certificate.c
 */

int ldap_certif_print LDAP_P(( PS ps, struct certificate *parm, int format ));
void ldap_print_algid LDAP_P(( PS ps, struct alg_id *parm, int format ));
struct certificate *ldap_str2cert LDAP_P(( char *str ));
void ldap_str2alg LDAP_P(( char *str, struct alg_id *alg ));
void certif_init LDAP_P(( void ));

/*
 * compare.c
 */

struct ds_compare_result;
int do_compare LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
void compare_result LDAP_P(( Sockbuf *sb, struct msg *m,
			     struct ds_compare_result *cr ));

/*
 * delete.c
 */

int do_delete LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
void delete_result LDAP_P(( Sockbuf *sb, struct msg *m ));

/*
 * error.c
 */

void print_error LDAP_P(( struct DSError *e ));
int x500err2ldaperr LDAP_P(( struct DSError *e, char **matched ));

/*
 * kerberos.c
 */

struct ds_bind_arg;
int kerberosv4_ldap_auth LDAP_P(( char *cred, long len ));
int kerberosv4_bindarg   LDAP_P(( struct ds_bind_arg *ba, DN dn, char *cred,
				  long len, u_long *nonce ));
int kerberos_check_mutual LDAP_P(( struct ds_bind_arg *res, u_long nonce ));

/*
 * main.c
 */

RETSIGTYPE log_and_exit LDAP_P(( int exitcode )) LDAP_GCCATTR((noreturn));

/*
 * message.c
 */

struct msg *add_msg LDAP_P(( int msgid, int msgtype, BerElement *ber,
	struct conn *dsaconn, int udp, struct sockaddr *clientaddr ));
struct msg *get_msg LDAP_P(( int uniqid ));
int del_msg LDAP_P(( struct msg *m ));
void send_msg LDAP_P(( struct conn *conn, Sockbuf *clientsb, int err, char *str ));
struct msg * get_cldap_msg LDAP_P(( int msgid, int msgtype, struct sockaddr *fromaddr ));

/*
 * modify.c
 */

struct ds_read_result;
int do_modify LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
int do_modify2 LDAP_P((Sockbuf *sb, struct msg *m, struct ds_read_result *rr));
Attr_Sequence get_as LDAP_P(( Sockbuf *clientsb, unsigned long op, struct msg *m,
			      char *type, struct berval **bvals ));
void modify_result LDAP_P(( Sockbuf *sb, struct msg *m ));
void modlist_free LDAP_P(( LDAPModList *mods ));

/*
 * modrdn.c
 */

int do_modrdn LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
void modrdn_result  LDAP_P((Sockbuf *sb, struct msg *m));

/*
 * request.c
 */

void client_request LDAP_P(( Sockbuf *clientsb, struct conn *dsaconn, int  udp ));
int do_request LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber,
	int *bound ));
int initiate_dap_operation LDAP_P(( int op, struct msg *m, void *arg ));
#ifdef LDAP_DEBUG
int trace_ber LDAP_P(( int tag, int len, char *ber,
		       FILE *trace_file, int prepend, int read_pdu ));
#endif

/*
 * result.c
 */

void dsa_response LDAP_P(( struct conn *dsaconn, Sockbuf *clientsb ));
int send_ldap_msgresult LDAP_P(( Sockbuf *sb, unsigned long tag, struct msg *m,
	int err, char *matched, char *text ));
int send_ldap_result LDAP_P(( Sockbuf *sb, unsigned long tag, int msgid, int err,
	char *matched, char *text ));

/*
 * search.c
 */

struct ds_search_result;
int do_search LDAP_P(( Sockbuf *clientsb, struct msg *m, BerElement *ber ));
void search_result LDAP_P(( Sockbuf *sb, struct msg *m,
			    struct ds_search_result *sr ));


/*
 * syntax.c
 */

void get_syntaxes LDAP_P(( void ));
int dn_print_real LDAP_P(( PS ps, DN dn, int format));
void ldap_dn_print LDAP_P(( PS ps, DN dn, DN base, int format));
int encode_dn LDAP_P(( BerElement *ber, DN dn, DN base));
int encode_attrs LDAP_P(( BerElement *ber, Attr_Sequence as ));
AttributeValue bv_octet2AttrV LDAP_P(( struct berval *bv ));
AttributeValue bv_asn2AttrV LDAP_P(( struct berval *bv ));
AttributeValue ldap_strdn2AttrV LDAP_P(( char *dnstr ));
DN ldap_str2dn LDAP_P(( char *str ));
RDN ldap_str2rdn LDAP_P(( char *rdnstr ));
AttributeValue ldap_str_at2AttrV LDAP_P(( char *str, AttributeType type ));
AttributeValue ldap_str2AttrV LDAP_P(( char *value, short syntax ));

/*
 * util.c
 */

void bprint LDAP_P(( char *data, int len ));
void charlist_free LDAP_P(( char **cl ));
int get_ava LDAP_P(( BerElement *ber, AVA *tava ));
int chase_referral LDAP_P(( Sockbuf *clientsb, struct msg *m, struct DSError *err,
	char **matched ));

#endif /* _proto_ldapd */

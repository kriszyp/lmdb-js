#ifndef _PROTO_LDAPD
#define _PROTO_LDAPD

/*
 * abandon.c
 */

int do_abandon( struct conn *dsaconn, BerElement *ber, int msgid );

/*
 * add.c
 */

int do_add( Sockbuf *clientsb, struct msg *m, BerElement *ber );

/*
 * association.c
 */

struct conn *conn_dup( struct conn *cn );
int conn_init();
void conn_free( struct conn *conn );
void conn_del( struct conn *conn );
void conn_badfds();
struct conn *conn_getfd( fd_set *fds );
void conn_add( struct conn *new );
struct conn *conn_find( struct conn *c );
void conn_add( struct conn *new );
void conn_close();
int isclosed( int ad );

/*
 * bind.c
 */

int do_bind( Sockbuf *clientsb, struct msg *m, BerElement *ber, int *bound );
int do_bind_real( struct conn *dsaconn, int *bound, char **matched );

/*
 * certificate.c
 */

int ldap_certif_print( PS ps, struct certificate *parm, int format );
void ldap_print_algid( PS ps, struct alg_id *parm, int format );
struct certificate *ldap_str2cert( char *str );
void ldap_str2alg( char *str, struct alg_id *alg );
void certif_init();

/*
 * compare.c
 */

int do_compare( Sockbuf *clientsb, struct msg *m, BerElement *ber );

/*
 * delete.c
 */

int do_delete( Sockbuf *clientsb, struct msg *m, BerElement *ber );

/*
 * error.c
 */

void print_error( struct DSError *e );
int x500err2ldaperr( struct DSError *e, char **matched );

/*
 * kerberos.c
 */

int kerberosv4_ldap_auth( char *cred, long len );

/*
 * main.c
 */

void log_and_exit( int exitcode );

/*
 * message.c
 */

struct msg *add_msg( int msgid, int msgtype, BerElement *ber,
	struct conn *dsaconn, int udp, struct sockaddr *clientaddr );
struct msg *get_msg( int uniqid );
int del_msg( struct msg *m );
void send_msg( struct conn *conn, Sockbuf *clientsb, int err, char *str );
struct msg * get_cldap_msg( int msgid, int msgtype, struct sockaddr *fromaddr );

/*
 * modify.c
 */

int do_modify( Sockbuf *clientsb, struct msg *m, BerElement *ber );
Attr_Sequence get_as( Sockbuf *clientsb, unsigned long op, struct msg *m,
	char *type, struct berval **bvals );
void modlist_free( LDAPMod *mods );

/*
 * modrdn.c
 */

int do_modrdn( Sockbuf *clientsb, struct msg *m, BerElement *ber );

/*
 * request.c
 */

void client_request( Sockbuf *clientsb, struct conn *dsaconn, int  udp );
int do_request( Sockbuf *clientsb, struct msg *m, BerElement *ber,
	int *bound );
int initiate_dap_operation( int op, struct msg *m, void *arg );

/*
 * result.c
 */

void dsa_response( struct conn *dsaconn, Sockbuf *clientsb );
int send_ldap_msgresult( Sockbuf *sb, unsigned long tag, struct msg *m,
	int err, char *matched, char *text );
int send_ldap_result( Sockbuf *sb, unsigned long tag, int msgid, int err,
	char *matched, char *text );

/*
 * search.c
 */

int do_search( Sockbuf *clientsb, struct msg *m, BerElement *ber );

/*
 * syntax.c
 */

void get_syntaxes();
int dn_print_real( PS ps, DN dn, int format);
void ldap_dn_print( PS ps, DN dn, DN base, int format);
int encode_dn( BerElement *ber, DN dn, DN base);
int encode_attrs( BerElement *ber, Attr_Sequence as );
AttributeValue bv_octet2AttrV( struct berval *bv );
AttributeValue bv_asn2AttrV( struct berval *bv );
AttributeValue ldap_strdn2AttrV( char *dnstr );
DN ldap_str2dn( char *str );
RDN ldap_str2rdn( char *rdnstr );
AttributeValue ldap_str_at2AttrV( char *str, AttributeType type );
AttributeValue ldap_str2AttrV( char *value, short syntax );

/*
 * util.c
 */

void bprint( char *data, int len );
void charlist_free( char **cl );
int get_ava( BerElement *ber, AVA *tava );
int chase_referral( Sockbuf *clientsb, struct msg *m, struct DSError *err,
	char **matched );

#endif /* _proto_ldapd */

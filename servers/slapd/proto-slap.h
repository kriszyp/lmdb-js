/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _PROTO_SLAP
#define _PROTO_SLAP

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/*
 * acl.c
 */

int access_allowed LDAP_P(( Backend *be, Connection *conn,
	Operation *op, Entry *e,
	char *attr, struct berval *val, int access ));

AccessControl * acl_get_applicable LDAP_P(( Backend *be,
	Operation *op, Entry *e,
	char *attr, int nmatches, regmatch_t *matches ));

int acl_access_allowed LDAP_P((
	AccessControl *a, char *attr, Backend *be, Connection *conn, Entry *e,
	struct berval *val, Operation *op, int  access, char *edn,
	regmatch_t *matches ));

int acl_check_modlist LDAP_P(( Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	LDAPModList *ml ));

/*
 * aclparse.c
 */

void parse_acl LDAP_P(( Backend *be,
	const char *fname,
	int lineno,
	int argc, char **argv ));
char * access2str LDAP_P(( int access ));
int str2access LDAP_P(( char *str ));

/*
 * attr.c
 */

void attr_free LDAP_P(( Attribute *a ));
Attribute *attr_dup LDAP_P(( Attribute *a ));
char * attr_normalize LDAP_P(( char *s ));
int attr_merge_fast LDAP_P(( Entry *e, char *type, struct berval **vals, int  nvals,
	int  naddvals, int  *maxvals, Attribute ***a ));
int attr_merge LDAP_P(( Entry *e, char *type, struct berval **vals ));
Attribute * attr_find LDAP_P(( Attribute *a, const char *type ));
int attr_delete LDAP_P(( Attribute **attrs, const char *type ));
int attr_syntax LDAP_P(( char *type ));
void attr_syntax_config LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
AttributeType * at_find LDAP_P(( const char *name ));
int at_find_in_list LDAP_P(( AttributeType *sat, AttributeType **list ));
int at_append_to_list LDAP_P(( AttributeType *sat, AttributeType ***listp ));
int at_delete_from_list LDAP_P(( int pos, AttributeType ***listp ));
int at_fake_if_needed LDAP_P(( char *name ));
int at_schema_info LDAP_P(( Entry *e ));
int at_add LDAP_P(( LDAP_ATTRIBUTE_TYPE *at, const char **err ));
char * at_canonical_name LDAP_P(( char * a_type ));

void attrs_free LDAP_P(( Attribute *a ));
Attribute *attrs_dup LDAP_P(( Attribute *a ));

/*
 * ava.c
 */

int get_ava LDAP_P(( BerElement *ber, Ava *ava ));
void ava_free LDAP_P(( Ava *ava, int freeit ));

/*
 * backend.c
 */

int backend_init LDAP_P((void));
int backend_add LDAP_P((BackendInfo *aBackendInfo));
int backend_num LDAP_P((Backend *be));
int backend_startup LDAP_P((Backend *be));
int backend_shutdown LDAP_P((Backend *be));
int backend_destroy LDAP_P((void));

BackendInfo * backend_info LDAP_P(( const char *type ));
BackendDB * backend_db_init LDAP_P(( const char *type ));

BackendDB * select_backend LDAP_P(( const char * dn ));

int be_issuffix LDAP_P(( Backend *be, const char *suffix ));
int be_isroot LDAP_P(( Backend *be, const char *ndn ));
int be_isroot_pw LDAP_P(( Backend *be, const char *ndn, struct berval *cred ));
char* be_root_dn LDAP_P(( Backend *be ));
int be_entry_release_rw LDAP_P(( Backend *be, Entry *e, int rw ));
#define be_entry_release_r( be, e ) be_entry_release_rw( be, e, 0 )
#define be_entry_release_w( be, e ) be_entry_release_rw( be, e, 1 )


extern int	backend_unbind LDAP_P((Connection *conn, Operation *op));

extern int	backend_connection_init LDAP_P((Connection *conn));
extern int	backend_connection_destroy LDAP_P((Connection *conn));

extern int	backend_group LDAP_P((Backend *be,
	Entry *target,
	const char *gr_ndn,
	const char *op_ndn,
	const char *objectclassValue,
	const char *groupattrName));

#ifdef SLAPD_SCHEMA_DN
/* temporary extern for temporary routine*/
extern Attribute *backend_subschemasubentry( Backend * );
#endif


/*
 * ch_malloc.c
 */

#ifdef CSRIMALLOC
#define ch_malloc malloc
#define ch_realloc realloc
#define ch_calloc calloc
#define ch_strdup strdup
#define ch_free free

#else
void * ch_malloc LDAP_P(( ber_len_t size ));
void * ch_realloc LDAP_P(( void *block, ber_len_t size ));
void * ch_calloc LDAP_P(( ber_len_t nelem, ber_len_t size ));
char * ch_strdup LDAP_P(( const char *string ));
void   ch_free LDAP_P(( void * ));

#ifndef CH_FREE
#undef free
#define free ch_free
#endif
#endif

/*
 * charray.c
 */

void charray_add LDAP_P(( char ***a, const char *s ));
void charray_merge LDAP_P(( char ***a, char **s ));
void charray_free LDAP_P(( char **array ));
int charray_inlist LDAP_P(( char **a, const char *s ));
char ** charray_dup LDAP_P(( char **a ));
char ** str2charray LDAP_P(( const char *str, const char *brkstr ));
char * charray2str LDAP_P(( char **a ));

/*
 * controls.c
 */
int get_ctrls LDAP_P((
	Connection *co,
	Operation *op,
	int senderrors ));

int get_manageDSAit LDAP_P(( Operation *op ));

/*
 * config.c
 */

int read_config LDAP_P(( const char *fname ));

/*
 * connection.c
 */
int connections_init LDAP_P((void));
int connections_shutdown LDAP_P((void));
int connections_destroy LDAP_P((void));
int connections_timeout_idle LDAP_P((time_t));

long connection_init LDAP_P((
	ber_socket_t s,
	const char* url,
	const char* dnsname,
	const char* peername,
	const char* sockname,
	int use_tls ));

void connection_closing LDAP_P(( Connection *c ));
int connection_state_closing LDAP_P(( Connection *c ));
char *connection_state2str LDAP_P(( int state ));

int connection_write LDAP_P((ber_socket_t s));
int connection_read LDAP_P((ber_socket_t s));

unsigned long connections_nextid(void);

Connection* connection_first LDAP_P((ber_socket_t *));
Connection* connection_next LDAP_P((Connection *, ber_socket_t *));
void connection_done LDAP_P((Connection *));

/*
 * dn.c
 */

char * dn_normalize LDAP_P(( char *dn ));
char * dn_normalize_case LDAP_P(( char *dn ));
char * dn_parent LDAP_P(( Backend *be, const char *dn ));
char ** dn_subtree LDAP_P(( Backend *be, const char *dn ));
char * dn_rdn LDAP_P(( Backend *be, char *dn ));
int dn_issuffix LDAP_P(( char *dn, char *suffix ));
#ifdef DNS_DN
int dn_type LDAP_P(( char *dn ));
#endif
int rdn_validate LDAP_P(( const char* str ));
char * rdn_attr_value LDAP_P(( char * rdn ));
char * rdn_attr_type LDAP_P(( char * rdn ));

void build_new_dn LDAP_P(( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn ));
/*
 * entry.c
 */

int entry_destroy LDAP_P((void));

Entry * str2entry LDAP_P(( char	*s ));
char * entry2str LDAP_P(( Entry *e, int *len ));
void entry_free LDAP_P(( Entry *e ));

int entry_cmp LDAP_P(( Entry *a, Entry *b ));
int entry_dn_cmp LDAP_P(( Entry *a, Entry *b ));
int entry_id_cmp LDAP_P(( Entry *a, Entry *b ));

/*
 * filter.c
 */

int get_filter LDAP_P(( Connection *conn, BerElement *ber, Filter **filt, char **fstr ));
void filter_free LDAP_P(( Filter *f ));
void filter_print LDAP_P(( Filter *f ));

/*
 * filterentry.c
 */

int test_filter LDAP_P(( Backend *be, Connection *conn, Operation *op, Entry *e,
	Filter	*f ));

/*
 * lock.c
 */

FILE * lock_fopen LDAP_P(( const char *fname, const char *type, FILE **lfp ));
int lock_fclose LDAP_P(( FILE *fp, FILE *lfp ));

/*
 * module.c
 */

#ifdef SLAPD_MODULES
int module_load LDAP_P(( const char* file_name, int argc, char *argv[] ));
int module_path LDAP_P(( const char* path ));
#endif /* SLAPD_MODULES */

/*
 * monitor.c
 */
extern char *supportedExtensions[];
extern char *supportedControls[];

void monitor_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

/*
 * operation.c
 */

void slap_op_free LDAP_P(( Operation *op ));
Operation * slap_op_alloc LDAP_P((
	BerElement *ber, ber_int_t msgid,
	ber_tag_t tag, ber_int_t id ));

int slap_op_add LDAP_P(( Operation **olist, Operation *op ));
int slap_op_remove LDAP_P(( Operation **olist, Operation *op ));
Operation * slap_op_pop LDAP_P(( Operation **olist ));

/*
 * phonetic.c
 */

char * first_word LDAP_P(( char *s ));
char * next_word LDAP_P(( char *s ));
char * word_dup LDAP_P(( char *w ));
char * phonetic LDAP_P(( char *s ));

/*
 * repl.c
 */

void replog LDAP_P(( Backend *be, Operation *op, char *dn, void *change ));

/*
 * result.c
 */

struct berval **get_entry_referrals LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e ));

void send_ldap_result LDAP_P((
	Connection *conn, Operation *op,
	int err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls ));

void send_ldap_disconnect LDAP_P((
	Connection *conn, Operation *op,
	int err, const char *text ));

void send_search_result LDAP_P((
	Connection *conn, Operation *op,
	int err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls,
	int nentries ));

int send_search_reference LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, struct berval **refs, int scope,
	LDAPControl **ctrls,
	struct berval ***v2refs ));

int send_search_entry LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, char **attrs, int attrsonly,
	LDAPControl **ctrls ));

int str2result LDAP_P(( char *s,
	int *code, char **matched, char **info ));

/*
 * sasl.c
 */
extern char **supportedSASLMechanisms;

int sasl_init(void);
int sasl_destroy(void);

/*
 * schema.c
 */

int oc_schema_check LDAP_P(( Entry *e ));
int oc_check_operational_attr LDAP_P(( const char *type ));
int oc_check_usermod_attr LDAP_P(( const char *type ));
int oc_check_no_usermod_attr LDAP_P(( const char *type ));
ObjectClass *oc_find LDAP_P((const char *ocname));
int oc_add LDAP_P((LDAP_OBJECT_CLASS *oc, const char **err));
Syntax *syn_find LDAP_P((const char *synname));
Syntax *syn_find_desc LDAP_P((const char *syndesc, int *slen));
int syn_add LDAP_P((LDAP_SYNTAX *syn, slap_syntax_check_func *check, const char **err));
MatchingRule *mr_find LDAP_P((const char *mrname));
int mr_add LDAP_P((LDAP_MATCHING_RULE *mr, slap_mr_normalize_func *normalize, slap_mr_compare_func *compare, const char **err));
int case_ignore_normalize LDAP_P((struct berval *val, struct berval **normalized));
int register_syntax LDAP_P((char *desc,	slap_syntax_check_func *check ));
int register_matching_rule LDAP_P((char * desc,	slap_mr_normalize_func *normalize, slap_mr_compare_func *compare));
void schema_info LDAP_P((Connection *conn, Operation *op, char **attrs, int attrsonly));
int schema_init LDAP_P((void));

int is_entry_objectclass LDAP_P(( Entry *, const char* objectclass ));
#define is_entry_alias(e)		is_entry_objectclass((e), "ALIAS")
#define is_entry_referral(e)	is_entry_objectclass((e), "REFERRAL")


/*
 * schemaparse.c
 */

void parse_oc_old LDAP_P(( Backend *be, const char *fname, int lineno, int argc, char **argv ));
void parse_oc LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
void parse_at LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
void parse_oidm LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
char *scherr2str LDAP_P((int code));
int dscompare LDAP_P(( const char *s1, const char *s2del, char delim ));
/*
 * str2filter.c
 */

Filter * str2filter LDAP_P(( char *str ));

/*
 * suffixalias.c
 */
char *suffix_alias LDAP_P(( Backend *be, char *ndn ));

/*
 * value.c
 */

int value_add_fast LDAP_P(( struct berval ***vals, struct berval **addvals, int nvals,
	int naddvals, int *maxvals ));
int value_add LDAP_P(( struct berval ***vals, struct berval **addvals ));
void value_normalize LDAP_P(( char *s, int syntax ));
int value_cmp LDAP_P(( struct berval *v1, struct berval *v2, int syntax,
	int normalize ));
int value_find LDAP_P(( struct berval **vals, struct berval *v, int syntax,
	int normalize ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
void slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

/*
 * Other...
 */

extern struct berval **default_referral;
extern char		*replogfile;
extern const char Versionstr[];
extern int		active_threads;
extern int		defsize;
extern int		deftime;
extern int		g_argc;
extern int		global_default_access;
extern int		global_readonly;
extern int		global_lastmod;
extern int		global_idletimeout;
extern int		global_schemacheck;
extern char		*global_realm;
extern int		lber_debug;
extern int		ldap_syslog;

extern ldap_pvt_thread_mutex_t	num_sent_mutex;
extern long		num_bytes_sent;
extern long		num_pdu_sent;
extern long		num_entries_sent;
extern long		num_refs_sent;

extern ldap_pvt_thread_mutex_t	num_ops_mutex;
extern long		num_ops_completed;
extern long		num_ops_initiated;

extern char   *slapd_pid_file;
extern char   *slapd_args_file;
extern char		**g_argv;
extern time_t	starttime;

time_t slap_get_time LDAP_P((void));

extern ldap_pvt_thread_mutex_t	active_threads_mutex;
extern ldap_pvt_thread_cond_t	active_threads_cond;

extern ldap_pvt_thread_mutex_t	entry2str_mutex;
extern ldap_pvt_thread_mutex_t	replog_mutex;

#ifdef SLAPD_CRYPT
extern ldap_pvt_thread_mutex_t	crypt_mutex;
#endif
extern ldap_pvt_thread_mutex_t	gmtime_mutex;

extern AccessControl *global_acl;

int	slap_init LDAP_P((int mode, char* name));
int	slap_startup LDAP_P(( Backend *be ));
int	slap_shutdown LDAP_P(( Backend *be ));
int	slap_destroy LDAP_P((void));

struct sockaddr_in;

extern int	slapd_daemon_init( char *urls, int port, int tls_port );
extern int	slapd_daemon_destroy(void);
extern int	slapd_daemon(void);

extern void slapd_set_write LDAP_P((ber_socket_t s, int wake));
extern void slapd_clr_write LDAP_P((ber_socket_t s, int wake));
extern void slapd_set_read LDAP_P((ber_socket_t s, int wake));
extern void slapd_clr_read LDAP_P((ber_socket_t s, int wake));

extern void slapd_remove LDAP_P((ber_socket_t s, int wake));

extern RETSIGTYPE slap_sig_shutdown LDAP_P((int sig));
extern RETSIGTYPE slap_sig_wake LDAP_P((int sig));

extern void	config_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

extern void	root_dse_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

extern int	do_abandon LDAP_P((Connection *conn, Operation *op));
extern int	do_add LDAP_P((Connection *conn, Operation *op));
extern int	do_bind LDAP_P((Connection *conn, Operation *op));
extern int	do_compare LDAP_P((Connection *conn, Operation *op));
extern int	do_delete LDAP_P((Connection *conn, Operation *op));
extern int	do_modify LDAP_P((Connection *conn, Operation *op));
extern int	do_modrdn LDAP_P((Connection *conn, Operation *op));
extern int	do_search LDAP_P((Connection *conn, Operation *op));
extern int	do_unbind LDAP_P((Connection *conn, Operation *op));
extern int	do_extended LDAP_P((Connection *conn, Operation *op));


extern ber_socket_t dtblsize;

LDAP_END_DECL

#endif /* _proto_slap */


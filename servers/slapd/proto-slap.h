#ifndef _PROTO_SLAP
#define _PROTO_SLAP

#include <ldap_cdefs.h>

/*
 * acl.c
 */

int access_allowed LDAP_P(( Backend *be, Connection *conn,
	Operation *op, Entry *e,
	char *attr, struct berval *val, int access ));

struct acl * acl_get_applicable LDAP_P(( Backend *be,
	Operation *op, Entry *e,
	char *attr, int nmatches, regmatch_t *matches ));

int acl_access_allowed LDAP_P(( struct acl *a, Backend *be, Connection *conn, Entry *e,
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

void parse_acl LDAP_P(( Backend *be, char *fname, int lineno, int argc, char **argv ));
char * access2str LDAP_P(( int access ));
int str2access LDAP_P(( char *str ));

/*
 * attr.c
 */

void attr_free LDAP_P(( Attribute *a ));
char * attr_normalize LDAP_P(( char *s ));
int attr_merge_fast LDAP_P(( Entry *e, char *type, struct berval **vals, int  nvals,
	int  naddvals, int  *maxvals, Attribute ***a ));
int attr_merge LDAP_P(( Entry *e, char *type, struct berval **vals ));
Attribute * attr_find LDAP_P(( Attribute *a, char *type ));
int attr_delete LDAP_P(( Attribute **attrs, char *type ));
int attr_syntax LDAP_P(( char *type ));
void attr_syntax_config LDAP_P(( char *fname, int lineno, int argc, char **argv ));
AttributeType * at_find LDAP_P(( char *name ));
int at_find_in_list LDAP_P(( AttributeType *sat, AttributeType **list ));
int at_append_to_list LDAP_P(( AttributeType *sat, AttributeType ***listp ));
int at_delete_from_list LDAP_P(( int pos, AttributeType ***listp ));
int at_fake_if_needed LDAP_P(( char *name ));
int at_schema_info LDAP_P(( Entry *e ));
int at_add LDAP_P(( LDAP_ATTRIBUTE_TYPE *at, char **err ));

/*
 * ava.c
 */

int get_ava LDAP_P(( BerElement *ber, Ava *ava ));
void ava_free LDAP_P(( Ava *ava, int freeit ));

/*
 * backend.c
 */

int backend_init LDAP_P((void));
int backend_startup LDAP_P((int dbnum));
int backend_shutdown LDAP_P((int dbnum));
int backend_destroy LDAP_P((void));

BackendInfo * backend_info LDAP_P(( char *type ));
BackendDB * backend_db_init LDAP_P(( char *type ));

BackendDB * select_backend LDAP_P(( char * dn ));

int be_issuffix LDAP_P(( Backend *be, char *suffix ));
int be_isroot LDAP_P(( Backend *be, char *ndn ));
int be_isroot_pw LDAP_P(( Backend *be, char *ndn, struct berval *cred ));
char* be_root_dn LDAP_P(( Backend *be ));
int be_entry_release_rw LDAP_P(( Backend *be, Entry *e, int rw ));
#define be_entry_release_r( be, e ) be_entry_release_rw( be, e, 0 )
#define be_entry_release_w( be, e ) be_entry_release_rw( be, e, 1 )


extern int	backend_unbind LDAP_P((Connection *conn, Operation *op));

extern int	backend_group LDAP_P((Backend *be,
	Entry *target,
	char *gr_ndn, char *op_ndn,
	char *objectclassValue, char *groupattrName));

/*
 * ch_malloc.c
 */

void * ch_malloc LDAP_P(( unsigned long size ));
void * ch_realloc LDAP_P(( void *block, unsigned long size ));
void * ch_calloc LDAP_P(( unsigned long nelem, unsigned long size ));
char * ch_strdup LDAP_P(( const char *string ));

/*
 * charray.c
 */

void charray_add LDAP_P(( char ***a, char *s ));
void charray_merge LDAP_P(( char ***a, char **s ));
void charray_free LDAP_P(( char **array ));
int charray_inlist LDAP_P(( char **a, char *s ));
char ** charray_dup LDAP_P(( char **a ));
char ** str2charray LDAP_P(( char *str, char *brkstr ));

/*
 * config.c
 */

int read_config LDAP_P(( char *fname ));

/*
 * connection.c
 */
int connections_init LDAP_P((void));
int connections_shutdown LDAP_P((void));
int connections_destroy LDAP_P((void));

long connection_init LDAP_P((
	int s,
	const char* name, const char* addr));

void connection_closing LDAP_P(( Connection *c ));
int connection_state_closing LDAP_P(( Connection *c ));

int connection_write LDAP_P((int s));
int connection_read LDAP_P((int s));

long connections_nextid(void);

Connection* connection_first LDAP_P((int *));
Connection* connection_next LDAP_P((Connection *, int *));
void connection_done LDAP_P((Connection *));

/*
 * dn.c
 */

char * dn_normalize LDAP_P(( char *dn ));
char * dn_normalize_case LDAP_P(( char *dn ));
char * dn_parent LDAP_P(( Backend *be, char *dn ));
char * dn_rdn LDAP_P(( Backend *be, char *dn ));
int dn_issuffix LDAP_P(( char *dn, char *suffix ));
int dn_type LDAP_P(( char *dn ));
char * dn_upcase LDAP_P(( char *dn ));
char * rdn_attr_value LDAP_P(( char * rdn ));
char * rdn_attr_type LDAP_P(( char * rdn ));
void build_new_dn LDAP_P(( char ** new_dn, char *e_dn, char * p_dn,
			   char * newrdn ));
/*
 * entry.c
 */

Entry * str2entry LDAP_P(( char	*s ));
char * entry2str LDAP_P(( Entry *e, int *len, int printid ));
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

FILE * lock_fopen LDAP_P(( char *fname, char *type, FILE **lfp ));
int lock_fclose LDAP_P(( FILE *fp, FILE *lfp ));

/*
 * monitor.c
 */

void monitor_info LDAP_P(( Connection *conn, Operation *op ));

/*
 * operation.c
 */

void slap_op_free LDAP_P(( Operation *op ));
Operation * slap_op_alloc LDAP_P((
	BerElement *ber, unsigned long msgid,
	unsigned long tag, long id ));

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

void replog LDAP_P(( Backend *be, int optype, char *dn, void *change, int flag ));

/*
 * result.c
 */

void send_ldap_result LDAP_P(( Connection *conn, Operation *op, int err, char *matched,
	char *text ));
void send_ldap_search_result LDAP_P(( Connection *conn, Operation *op, int err,
	char *matched, char *text, int nentries ));

/*
 * schema.c
 */

int oc_schema_check LDAP_P(( Entry *e ));
ObjectClass *oc_find LDAP_P((char *ocname));
int oc_add LDAP_P((LDAP_OBJECT_CLASS *oc, char **err));
void schema_info LDAP_P((Connection *conn, Operation *op, char **attrs, int attrsonly));


/*
 * schemaparse.c
 */

void parse_oc_old LDAP_P(( Backend *be, char *fname, int lineno, int argc, char **argv ));
void parse_oc LDAP_P(( char *fname, int lineno, char * line ));
void parse_at LDAP_P(( char *fname, int lineno, char *line ));

/*
 * str2filter.c
 */

Filter * str2filter LDAP_P(( char *str ));

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
 * suffixAlias.c
 */
char *suffixAlias LDAP_P(( char *dn, Operation *op, Backend *be ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
void slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

/*
 * Other...
 */

extern char		*default_referral;
extern char		*replogfile;
extern const char Versionstr[];
extern int		active_threads;
extern int		defsize;
extern int		deftime;
extern int		g_argc;
extern int		global_default_access;
extern int		global_lastmod;
extern int		global_schemacheck;
extern int		lber_debug;
extern int		ldap_syslog;

extern ldap_pvt_thread_mutex_t	num_sent_mutex;
extern long		num_bytes_sent;
extern long		num_entries_sent;

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

extern struct acl		*global_acl;

extern int	slap_init LDAP_P((int mode, char* name));
extern int	slap_startup LDAP_P((int dbnum));
extern int	slap_shutdown LDAP_P((int dbnum));
extern int	slap_destroy LDAP_P((void));

struct sockaddr_in;
extern int	set_socket LDAP_P((struct sockaddr_in *addr));
extern int	slapd_daemon LDAP_P((int inetd, int tcps));

extern void slapd_set_write LDAP_P((int s, int wake));
extern void slapd_clr_write LDAP_P((int s, int wake));
extern void slapd_set_read LDAP_P((int s, int wake));
extern void slapd_clr_read LDAP_P((int s, int wake));

extern void	slap_set_shutdown LDAP_P((int sig));
extern void	slap_do_nothing   LDAP_P((int sig));

extern void	config_info LDAP_P((Connection *conn, Operation *op));
extern void	root_dse_info LDAP_P((Connection *conn, Operation *op, char **attrs, int attrsonly));
extern void	do_abandon LDAP_P((Connection *conn, Operation *op));
extern void	do_add LDAP_P((Connection *conn, Operation *op));
extern void	do_bind LDAP_P((Connection *conn, Operation *op));
extern void	do_compare LDAP_P((Connection *conn, Operation *op));
extern void	do_delete LDAP_P((Connection *conn, Operation *op));
extern void	do_modify LDAP_P((Connection *conn, Operation *op));
extern void	do_modrdn LDAP_P((Connection *conn, Operation *op));
extern void	do_search LDAP_P((Connection *conn, Operation *op));
extern void	do_unbind LDAP_P((Connection *conn, Operation *op));

extern int send_search_entry LDAP_P((Backend *be, Connection *conn, Operation *op, Entry *e, char **attrs, int attrsonly));
extern int str2result LDAP_P(( char *s, int *code, char **matched, char **info ));

extern int dtblsize;

#endif /* _proto_slap */


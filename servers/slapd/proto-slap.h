#ifndef _PROTO_SLAP
#define _PROTO_SLAP

#include <ldap_cdefs.h>

/*
 * acl.c
 */

int access_allowed LDAP_P(( Backend *be, Connection *conn, Operation *op, Entry *e,
	char *attr, struct berval *val, char *dn, int  access ));

struct acl * acl_get_applicable LDAP_P(( Backend *be, Operation *op, Entry *e,
	char *attr, char *edn, int nmatches, regmatch_t *matches ));
int acl_access_allowed LDAP_P(( struct acl *a, Backend *be, Connection *conn, Entry *e,
	struct berval *val, Operation *op, int  access, char *edn,
	regmatch_t *matches ));

int acl_check_mods LDAP_P(( Backend *be, Connection *conn, Operation *op, Entry *e,
	LDAPMod *mods ));

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

/*
 * ava.c
 */

int get_ava LDAP_P(( BerElement *ber, Ava *ava ));
void ava_free LDAP_P(( Ava *ava, int freeit ));

/*
 * backend.c
 */

Backend * new_backend LDAP_P(( char *type ));
Backend * select_backend LDAP_P(( char * dn ));
int be_issuffix LDAP_P(( Backend *be, char *suffix ));
int be_isroot LDAP_P(( Backend *be, char *dn ));
int be_isroot_pw LDAP_P(( Backend *be, char *dn, struct berval *cred ));
void be_close LDAP_P(( void ));

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

void read_config LDAP_P(( char *fname, Backend **bep, FILE *pfp ));

/*
 * connection.c
 */

void connection_activity LDAP_P(( Connection *conn ));

/*
 * dn.c
 */

char * dn_normalize LDAP_P(( char *dn ));
char * dn_normalize_case LDAP_P(( char *dn ));
char * dn_parent LDAP_P(( Backend *be, char *dn ));
int dn_issuffix LDAP_P(( char *dn, char *suffix ));
int dn_type LDAP_P(( char *dn ));
char * dn_upcase LDAP_P(( char *dn ));

/*
 * entry.c
 */

Entry * str2entry LDAP_P(( char	*s ));
char * entry2str LDAP_P(( Entry *e, int *len, int printid ));
void entry_free LDAP_P(( Entry *e ));

int entry_rdwr_lock LDAP_P(( Entry *e, int rw ));
int entry_rdwr_rlock LDAP_P(( Entry *e ));
int entry_rdwr_wlock LDAP_P(( Entry *e ));
int entry_rdwr_unlock LDAP_P(( Entry *e, int rw ));
int entry_rdwr_runlock LDAP_P(( Entry *e ));
int entry_rdwr_wunlock LDAP_P(( Entry *e ));
int entry_rdwr_init LDAP_P(( Entry *e ));

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

void op_free LDAP_P(( Operation *op ));
Operation * op_add LDAP_P(( Operation **olist, BerElement *ber, unsigned long msgid,
	unsigned long tag, char *dn, int id, int connid ));
void op_delete LDAP_P(( Operation **olist, Operation *op ));

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
void close_connection LDAP_P(( Connection *conn, int opconnid, int opid ));

/*
 * schema.c
 */

int oc_schema_check LDAP_P(( Entry *e ));

/*
 * schemaparse.c
 */

void parse_oc LDAP_P(( Backend *be, char *fname, int lineno, int argc, char **argv ));

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
 * Other...
 */

extern char		**g_argv;
extern char		*default_referral;
extern char		*replogfile;
extern char		Versionstr[];
extern int		active_threads;
extern int		defsize;
extern int		deftime;
extern int		g_argc;
extern int		global_default_access;
extern int		global_lastmod;
extern int		global_schemacheck;
extern int		lber_debug;
extern int		ldap_syslog;
extern int		num_conns;
extern int		slapd_shutdown;
extern long		num_bytes_sent;
extern long		num_entries_sent;
extern long		ops_completed;
extern long		ops_initiated;
extern pthread_mutex_t	active_threads_mutex;
extern pthread_mutex_t	currenttime_mutex;
extern pthread_mutex_t	entry2str_mutex;
extern pthread_mutex_t	new_conn_mutex;
extern pthread_mutex_t	num_sent_mutex;
extern pthread_mutex_t	ops_mutex;
extern pthread_mutex_t	replog_mutex;
#ifdef SLAPD_CRYPT
extern pthread_mutex_t	crypt_mutex;
#endif
extern pthread_t	listener_tid;
extern struct acl	*global_acl;
extern struct objclass	*global_oc;
extern time_t		currenttime;

extern int	be_group LDAP_P((Backend *be, char *bdn, char *edn, char *objectclassValue, char *groupattrName));
extern void	init LDAP_P((void));
extern void	be_unbind LDAP_P((Connection *conn, Operation *op));
extern void	config_info LDAP_P((Connection *conn, Operation *op));
extern void	do_abandon LDAP_P((Connection *conn, Operation *op));
extern void	do_add LDAP_P((Connection *conn, Operation *op));
extern void	do_bind LDAP_P((Connection *conn, Operation *op));
extern void	do_compare LDAP_P((Connection *conn, Operation *op));
extern void	do_delete LDAP_P((Connection *conn, Operation *op));
extern void	do_modify LDAP_P((Connection *conn, Operation *op));
extern void	do_modrdn LDAP_P((Connection *conn, Operation *op));
extern void	do_search LDAP_P((Connection *conn, Operation *op));
extern void	do_unbind LDAP_P((Connection *conn, Operation *op));
extern void *	slapd_daemon LDAP_P((void *port));

extern int		nbackends;
extern Backend		*backends;
extern int send_search_entry LDAP_P((Backend *be, Connection *conn, Operation *op, Entry *e, char **attrs, int attrsonly));
extern int str2result LDAP_P(( char *s, int *code, char **matched, char **info ));

#if defined( SLAPD_MONITOR_DN )
extern Connection	*c;
extern int		dtblsize;
extern time_t		starttime;
#endif

#ifdef SLAPD_LDBM
extern int  ldbm_back_bind   LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, int method, struct berval *cred ));
extern void ldbm_back_unbind LDAP_P((Backend *be, Connection *c, Operation *o ));
extern int  ldbm_back_search LDAP_P((Backend *be, Connection *c, Operation *o, char *base, int scope, int deref, int slimit, int tlimit, Filter *f, char *filterstr, char **attrs, int attrsonly));
extern int  ldbm_back_compare LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, Ava *ava));
extern int  ldbm_back_modify LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, LDAPMod *m));
extern int  ldbm_back_modrdn LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, char *newrdn, int deleteoldrdn ));
extern int  ldbm_back_add    LDAP_P((Backend *be, Connection *c, Operation *o, Entry *e));
extern int  ldbm_back_delete LDAP_P((Backend *be, Connection *c, Operation *o, char *dn));
extern void ldbm_back_abandon LDAP_P((Backend *be, Connection *c, Operation *o, int msgid));
extern void ldbm_back_config LDAP_P((Backend *be, char *fname, int lineno, int argc, char **argv ));
extern void ldbm_back_init   LDAP_P((Backend *be));
extern void ldbm_back_close  LDAP_P((Backend *be));
extern int  ldbm_back_group  LDAP_P((Backend *be, char *bdn, char *edn, char *objectclassValue, char *groupattrName ));
#endif

#ifdef SLAPD_PASSWD
extern int  passwd_back_search LDAP_P((Backend *be, Connection *c, Operation *o, char *base, int scope, int deref, int slimit, int tlimit, Filter *f, char *filterstr, char **attrs, int attrsonly));
extern void passwd_back_config LDAP_P((Backend *be, char *fname, int lineno, int argc, char **argv ));
#endif

#ifdef SLAPD_SHELL
extern int  shell_back_bind   LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, int method, struct berval *cred ));
extern void shell_back_unbind LDAP_P((Backend *be, Connection *c, Operation *o ));
extern int  shell_back_search LDAP_P((Backend *be, Connection *c, Operation *o, char *base, int scope, int deref, int slimit, int tlimit, Filter *f, char *filterstr, char **attrs, int attrsonly));
extern int  shell_back_compare LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, Ava *ava));
extern int  shell_back_modify LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, LDAPMod *m));
extern int  shell_back_modrdn LDAP_P((Backend *be, Connection *c, Operation *o, char *dn, char *newrdn, int deleteoldrdn ));
extern int  shell_back_add    LDAP_P((Backend *be, Connection *c, Operation *o, Entry *e));
extern int  shell_back_delete LDAP_P((Backend *be, Connection *c, Operation *o, char *dn));
extern void shell_back_abandon LDAP_P((Backend *be, Connection *c, Operation *o, int msgid));
extern void shell_back_config LDAP_P((Backend *be, char *fname, int lineno, int argc, char **argv ));
extern void shell_back_init   LDAP_P((Backend *be));
#endif

#endif /* _proto_slap */

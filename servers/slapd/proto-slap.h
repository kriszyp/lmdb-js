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
void be_close LDAP_P(());

/*
 * ch_malloc.c
 */

char * ch_malloc LDAP_P(( unsigned long size ));
char * ch_realloc LDAP_P(( char *block, unsigned long size ));
char * ch_calloc LDAP_P(( unsigned long nelem, unsigned long size ));

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
int value_ncmp LDAP_P(( struct berval *v1, struct berval *v2, int syntax, int len,
	int normalize ));
int value_find LDAP_P(( struct berval **vals, struct berval *v, int syntax,
	int normalize ));

#endif /* _proto_slap */

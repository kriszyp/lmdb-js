#ifndef _PROTO_SLAP
#define _PROTO_SLAP

/*
 * acl.c
 */

int access_allowed( Backend *be, Connection *conn, Operation *op, Entry *e,
	char *attr, struct berval *val, char *dn, int  access );

struct acl * acl_get_applicable( Backend *be, Operation *op, Entry *e,
	char *attr, char *edn, int nmatches, regmatch_t *matches );
int acl_access_allowed( struct acl *a, Backend *be, Connection *conn, Entry *e,
	struct berval *val, Operation *op, int  access, char *edn,
	regmatch_t *matches );

int acl_check_mods( Backend *be, Connection *conn, Operation *op, Entry *e,
	LDAPMod *mods );

/*
 * aclparse.c
 */

void parse_acl( Backend *be, char *fname, int lineno, int argc, char **argv );
char * access2str( int access );
int str2access( char *str );

/*
 * attr.c
 */

void attr_free( Attribute *a );
char * attr_normalize( char *s );
int attr_merge_fast( Entry *e, char *type, struct berval **vals, int  nvals,
	int  naddvals, int  *maxvals, Attribute ***a );
int attr_merge( Entry *e, char *type, struct berval **vals );
Attribute * attr_find( Attribute *a, char *type );
int attr_delete( Attribute **attrs, char *type );
int attr_syntax( char *type );
void attr_syntax_config( char *fname, int lineno, int argc, char **argv );

/*
 * ava.c
 */

int get_ava( BerElement *ber, Ava *ava );
void ava_free( Ava *ava, int freeit );

/*
 * backend.c
 */

Backend * new_backend( char *type );
Backend * select_backend( char * dn );
int be_issuffix( Backend *be, char *suffix );
int be_isroot( Backend *be, char *dn );
int be_isroot_pw( Backend *be, char *dn, struct berval *cred );
void be_close();

/*
 * ch_malloc.c
 */

char * ch_malloc( unsigned long size );
char * ch_realloc( char *block, unsigned long size );
char * ch_calloc( unsigned long nelem, unsigned long size );

/*
 * charray.c
 */

void charray_add( char ***a, char *s );
void charray_merge( char ***a, char **s );
void charray_free( char **array );
int charray_inlist( char **a, char *s );
char ** charray_dup( char **a );
char ** str2charray( char *str, char *brkstr );

/*
 * config.c
 */

void read_config( char *fname, Backend **bep, FILE *pfp );

/*
 * connection.c
 */

void connection_activity( Connection *conn );

/*
 * dn.c
 */

char * dn_normalize( char *dn );
char * dn_normalize_case( char *dn );
char * dn_parent( Backend *be, char *dn );
int dn_issuffix( char *dn, char *suffix );
int dn_type( char *dn );
char * dn_upcase( char *dn );

/*
 * entry.c
 */

Entry * str2entry( char	*s );
char * entry2str( Entry *e, int *len, int printid );
void entry_free( Entry *e );

/*
 * filter.c
 */

int get_filter( Connection *conn, BerElement *ber, Filter **filt, char **fstr );
void filter_free( Filter *f );
void filter_print( Filter *f );

/*
 * filterentry.c
 */

int test_filter( Backend *be, Connection *conn, Operation *op, Entry *e,
	Filter	*f );

/*
 * lock.c
 */

FILE * lock_fopen( char *fname, char *type, FILE **lfp );
int lock_fclose( FILE *fp, FILE *lfp );

/*
 * monitor.c
 */

void monitor_info( Connection *conn, Operation *op );

/*
 * operation.c
 */

void op_free( Operation *op );
Operation * op_add( Operation **olist, BerElement *ber, unsigned long msgid,
	unsigned long tag, char *dn, int id, int connid );
void op_delete( Operation **olist, Operation *op );

/*
 * phonetic.c
 */

char * first_word( char *s );
char * next_word( char *s );
char * word_dup( char *w );
char * phonetic( char *s );

/*
 * repl.c
 */

void replog( Backend *be, int optype, char *dn, void *change, int flag );

/*
 * result.c
 */

void send_ldap_result( Connection *conn, Operation *op, int err, char *matched,
	char *text );
void send_ldap_search_result( Connection *conn, Operation *op, int err,
	char *matched, char *text, int nentries );
void close_connection( Connection *conn, int opconnid, int opid );

/*
 * schema.c
 */

int oc_schema_check( Entry *e );

/*
 * schemaparse.c
 */

void parse_oc( Backend *be, char *fname, int lineno, int argc, char **argv );

/*
 * str2filter.c
 */

Filter * str2filter( char *str );

/*
 * value.c
 */

int value_add_fast( struct berval ***vals, struct berval **addvals, int nvals,
	int naddvals, int *maxvals );
int value_add( struct berval ***vals, struct berval **addvals );
void value_normalize( char *s, int syntax );
int value_cmp( struct berval *v1, struct berval *v2, int syntax,
	int normalize );
int value_ncmp( struct berval *v1, struct berval *v2, int syntax, int len,
	int normalize );
int value_find( struct berval **vals, struct berval *v, int syntax,
	int normalize );

#endif /* _proto_slap */

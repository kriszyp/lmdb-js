/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _PROTO_SLAP
#define _PROTO_SLAP

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

LDAP_SLAPD_F( int ) schema_init_done;
LDAP_SLAPD_F( struct slap_internal_schema ) slap_schema;

LDAP_SLAPD_F (int) slap_str2ad LDAP_P((
	const char *,
	AttributeDescription **ad,
	const char **text ));

LDAP_SLAPD_F (int) slap_bv2ad LDAP_P((
	struct berval *bv,
	AttributeDescription **ad,
	const char **text ));

LDAP_SLAPD_F (AttributeDescription *) ad_dup LDAP_P((
	AttributeDescription *desc ));

LDAP_SLAPD_F (void) ad_free LDAP_P((
	AttributeDescription *desc,
	int freeit ));

#define ad_cmp(l,r)	( strcasecmp( \
	(l)->ad_cname->bv_val, (r)->ad_cname->bv_val ))

LDAP_SLAPD_F (int) is_ad_subtype LDAP_P((
	AttributeDescription *sub,
	AttributeDescription *super ));

LDAP_SLAPD_F (int) ad_inlist LDAP_P((
	AttributeDescription *desc,
	char **attrs ));

LDAP_SLAPD_F (int) slap_str2undef_ad LDAP_P((
	const char *,
	AttributeDescription **ad,
	const char **text ));

LDAP_SLAPD_F (int) slap_bv2undef_ad LDAP_P((
	struct berval *bv,
	AttributeDescription **ad,
	const char **text ));

/*
 * acl.c
 */

LDAP_SLAPD_F (int) access_allowed LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, AttributeDescription *desc, struct berval *val,
	slap_access_t access ));
LDAP_SLAPD_F (int) acl_check_modlist LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, Modifications *ml ));

LDAP_SLAPD_F (void) acl_append( AccessControl **l, AccessControl *a );

/*
 * aclparse.c
 */

LDAP_SLAPD_F (void) parse_acl LDAP_P(( Backend *be,
	const char *fname, int lineno,
	int argc, char **argv ));

LDAP_SLAPD_F (char *) access2str LDAP_P(( slap_access_t access ));
LDAP_SLAPD_F (slap_access_t) str2access LDAP_P(( const char *str ));

#define ACCESSMASK_MAXLEN	sizeof("unknown (+wrscan)")
LDAP_SLAPD_F (char *) accessmask2str LDAP_P(( slap_mask_t mask, char* ));
LDAP_SLAPD_F (slap_mask_t) str2accessmask LDAP_P(( const char *str ));

/*
 * at.c
 */

LDAP_SLAPD_F (void) at_config LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
LDAP_SLAPD_F (AttributeType *) at_find LDAP_P(( const char *name ));
LDAP_SLAPD_F (int) at_find_in_list LDAP_P(( AttributeType *sat, AttributeType **list ));
LDAP_SLAPD_F (int) at_append_to_list LDAP_P(( AttributeType *sat, AttributeType ***listp ));
LDAP_SLAPD_F (int) at_delete_from_list LDAP_P(( int pos, AttributeType ***listp ));
LDAP_SLAPD_F (int) at_schema_info LDAP_P(( Entry *e ));
LDAP_SLAPD_F (int) at_add LDAP_P(( LDAPAttributeType *at, const char **err ));

LDAP_SLAPD_F (int) is_at_subtype LDAP_P((
	AttributeType *sub,
	AttributeType *super ));

LDAP_SLAPD_F (int) is_at_syntax LDAP_P((
	AttributeType *at,
	const char *oid ));

#	define at_canonical_name(at) ((at)->sat_cname)	


/*
 * attr.c
 */

LDAP_SLAPD_F (void) attr_free LDAP_P(( Attribute *a ));
LDAP_SLAPD_F (Attribute *) attr_dup LDAP_P(( Attribute *a ));

LDAP_SLAPD_F (int) attr_merge LDAP_P(( Entry *e,
	AttributeDescription *desc,
	struct berval **vals ));
LDAP_SLAPD_F (Attribute *) attrs_find LDAP_P(( Attribute *a, AttributeDescription *desc ));
LDAP_SLAPD_F (Attribute *) attr_find LDAP_P(( Attribute *a, AttributeDescription *desc ));
LDAP_SLAPD_F (int) attr_delete LDAP_P(( Attribute **attrs, AttributeDescription *desc ));

LDAP_SLAPD_F (void) attrs_free LDAP_P(( Attribute *a ));
LDAP_SLAPD_F (Attribute *) attrs_dup LDAP_P(( Attribute *a ));


/*
 * ava.c
 */
LDAP_SLAPD_F (int) get_ava LDAP_P((
	BerElement *ber,
	AttributeAssertion **ava,
	unsigned usage,
	const char **text ));
LDAP_SLAPD_F (void) ava_free LDAP_P((
	AttributeAssertion *ava,
	int freeit ));

/*
 * backend.c
 */

LDAP_SLAPD_F (int) backend_init LDAP_P((void));
LDAP_SLAPD_F (int) backend_add LDAP_P((BackendInfo *aBackendInfo));
LDAP_SLAPD_F (int) backend_num LDAP_P((Backend *be));
LDAP_SLAPD_F (int) backend_startup LDAP_P((Backend *be));
LDAP_SLAPD_F (int) backend_shutdown LDAP_P((Backend *be));
LDAP_SLAPD_F (int) backend_destroy LDAP_P((void));

LDAP_SLAPD_F (BackendInfo *) backend_info LDAP_P(( const char *type ));
LDAP_SLAPD_F (BackendDB *) backend_db_init LDAP_P(( const char *type ));

LDAP_SLAPD_F (BackendDB *) select_backend LDAP_P(( const char * dn ));

LDAP_SLAPD_F (int) be_issuffix LDAP_P(( Backend *be, const char *suffix ));
LDAP_SLAPD_F (int) be_isroot LDAP_P(( Backend *be, const char *ndn ));
LDAP_SLAPD_F (int) be_isroot_pw LDAP_P(( Backend *be, const char *ndn, struct berval *cred ));
LDAP_SLAPD_F (char *) be_root_dn LDAP_P(( Backend *be ));
LDAP_SLAPD_F (int) be_entry_release_rw LDAP_P(( Backend *be, Entry *e, int rw ));
#define be_entry_release_r( be, e ) be_entry_release_rw( be, e, 0 )
#define be_entry_release_w( be, e ) be_entry_release_rw( be, e, 1 )

LDAP_SLAPD_F (int) backend_unbind LDAP_P((Connection *conn, Operation *op));

LDAP_SLAPD_F( int )	backend_check_controls LDAP_P((
	Backend *be,
	Connection *conn,
	Operation *op,
	const char **text ));

LDAP_SLAPD_F( int )	backend_check_referrals LDAP_P((
	Backend *be,
	Connection *conn,
	Operation *op,
	const char *dn,
	const char *ndn ));

LDAP_SLAPD_F (int) backend_connection_init LDAP_P((Connection *conn));
LDAP_SLAPD_F (int) backend_connection_destroy LDAP_P((Connection *conn));

LDAP_SLAPD_F (int) backend_group LDAP_P((Backend *be,
	Entry *target,
	const char *gr_ndn,
	const char *op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at
));

LDAP_SLAPD_F (int) backend_attribute LDAP_P((Backend *be,
	Connection *conn,
	Operation *op,
	Entry *target,
	const char *e_ndn,
	AttributeDescription *entry_at,
	struct berval ***vals
));

LDAP_SLAPD_F (Attribute *) backend_operational( Backend *, Entry * );



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
LDAP_SLAPD_F (void *) ch_malloc LDAP_P(( ber_len_t size ));
LDAP_SLAPD_F (void *) ch_realloc LDAP_P(( void *block, ber_len_t size ));
LDAP_SLAPD_F (void *) ch_calloc LDAP_P(( ber_len_t nelem, ber_len_t size ));
LDAP_SLAPD_F (char *) ch_strdup LDAP_P(( const char *string ));
LDAP_SLAPD_F (void) ch_free LDAP_P(( void * ));

#ifndef CH_FREE
#undef free
#define free ch_free
#endif
#endif

/*
 * charray.c
 */

LDAP_SLAPD_F (void) charray_add LDAP_P(( char ***a, const char *s ));
LDAP_SLAPD_F (void) charray_merge LDAP_P(( char ***a, char **s ));
LDAP_SLAPD_F (void) charray_free LDAP_P(( char **array ));
LDAP_SLAPD_F (int) charray_inlist LDAP_P(( char **a, const char *s ));
LDAP_SLAPD_F (char **) charray_dup LDAP_P(( char **a ));
LDAP_SLAPD_F (char **) str2charray LDAP_P(( const char *str, const char *brkstr ));

/*
 * controls.c
 */
LDAP_SLAPD_F (int) get_ctrls LDAP_P((
	Connection *co,
	Operation *op,
	int senderrors ));

LDAP_SLAPD_F (int) get_manageDSAit LDAP_P(( Operation *op ));

/*
 * config.c
 */

LDAP_SLAPD_F (int) read_config LDAP_P(( const char *fname ));


/*
 * index.c
 */
LDAP_SLAPD_F (int) slap_index2prefix LDAP_P(( int indextype ));
LDAP_SLAPD_F (int) slap_str2index LDAP_P(( const char *str, slap_mask_t *idx ));

/*
 * connection.c
 */
LDAP_SLAPD_F (int) connections_init LDAP_P((void));
LDAP_SLAPD_F (int) connections_shutdown LDAP_P((void));
LDAP_SLAPD_F (int) connections_destroy LDAP_P((void));
LDAP_SLAPD_F (int) connections_timeout_idle LDAP_P((time_t));

LDAP_SLAPD_F (long) connection_init LDAP_P((
	ber_socket_t s,
	const char* url,
	const char* dnsname,
	const char* peername,
	const char* sockname,
	int use_tls,
	slap_ssf_t ssf,
	char *id ));

LDAP_SLAPD_F (void) connection_closing LDAP_P(( Connection *c ));
LDAP_SLAPD_F (int) connection_state_closing LDAP_P(( Connection *c ));
LDAP_SLAPD_F (const char *) connection_state2str LDAP_P(( int state )) LDAP_GCCATTR((const));

LDAP_SLAPD_F (int) connection_write LDAP_P((ber_socket_t s));
LDAP_SLAPD_F (int) connection_read LDAP_P((ber_socket_t s));

LDAP_SLAPD_F (unsigned long) connections_nextid(void);

LDAP_SLAPD_F (Connection *) connection_first LDAP_P((ber_socket_t *));
LDAP_SLAPD_F (Connection *) connection_next LDAP_P((Connection *, ber_socket_t *));
LDAP_SLAPD_F (void) connection_done LDAP_P((Connection *));

/*
 * dn.c
 */

LDAP_SLAPD_F (char *) dn_validate LDAP_P(( char *dn ));
LDAP_SLAPD_F (char *) dn_normalize LDAP_P(( char *dn ));
LDAP_SLAPD_F (char *) dn_parent LDAP_P(( Backend *be, const char *dn ));
LDAP_SLAPD_F (char **) dn_subtree LDAP_P(( Backend *be, const char *dn ));
LDAP_SLAPD_F (char *) dn_rdn LDAP_P(( Backend *be, const char *dn ));
LDAP_SLAPD_F (int) dn_issuffix LDAP_P(( const char *dn, const char *suffix ));
LDAP_SLAPD_F (int) rdn_validate LDAP_P(( const char* str ));
LDAP_SLAPD_F (char *) rdn_attr_value LDAP_P(( const char * rdn ));
LDAP_SLAPD_F (char *) rdn_attr_type LDAP_P(( const char * rdn ));

LDAP_SLAPD_F (void) build_new_dn LDAP_P(( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn ));
/*
 * entry.c
 */

LDAP_SLAPD_F (int) entry_destroy LDAP_P((void));

LDAP_SLAPD_F (Entry *) str2entry LDAP_P(( char	*s ));
LDAP_SLAPD_F (char *) entry2str LDAP_P(( Entry *e, int *len ));
LDAP_SLAPD_F (void) entry_free LDAP_P(( Entry *e ));

LDAP_SLAPD_F (int) entry_cmp LDAP_P(( Entry *a, Entry *b ));
LDAP_SLAPD_F (int) entry_dn_cmp LDAP_P(( Entry *a, Entry *b ));
LDAP_SLAPD_F (int) entry_id_cmp LDAP_P(( Entry *a, Entry *b ));

/*
 * extended.c
 */

typedef int (*SLAP_EXTOP_MAIN_FN) LDAP_P((
	Connection *conn, Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl *** rspctrls,
	const char ** text,
	struct berval *** refs ));

typedef int (*SLAP_EXTOP_GETOID_FN) LDAP_P((
	int index, char *oid, int blen ));

LDAP_SLAPD_F (int) load_extension LDAP_P((const void *module, const char *file_name));
LDAP_SLAPD_F (char *) get_supported_extension LDAP_P((int index));

LDAP_SLAPD_F (int) load_extop LDAP_P((
	const char *ext_oid,
	SLAP_EXTOP_MAIN_FN ext_main ));

LDAP_SLAPD_F (int) extops_init LDAP_P(( void ));

LDAP_SLAPD_F (int) extops_kill LDAP_P(( void ));

LDAP_SLAPD_F (char *) get_supported_extop LDAP_P((int index));

/*
 * filter.c
 */

LDAP_SLAPD_F (int) get_filter LDAP_P((
	Connection *conn,
	BerElement *ber,
	Filter **filt,
	char **fstr,
	const char **text ));

LDAP_SLAPD_F (void) filter_free LDAP_P(( Filter *f ));
LDAP_SLAPD_F (void) filter_print LDAP_P(( Filter *f ));

/*
 * filterentry.c
 */

LDAP_SLAPD_F (int) test_filter LDAP_P((
	Backend *be, Connection *conn, Operation *op, Entry *e, Filter	*f ));

/*
 * lock.c
 */

LDAP_SLAPD_F (FILE *) lock_fopen LDAP_P(( const char *fname, const char *type, FILE **lfp ));
LDAP_SLAPD_F (int) lock_fclose LDAP_P(( FILE *fp, FILE *lfp ));


/*
 * modify.c
 *	should be relocated to separate file
 */
LDAP_SLAPD_F( void ) slap_mod_free LDAP_P(( Modification *mod, int freeit ));
LDAP_SLAPD_F( void ) slap_mods_free LDAP_P(( Modifications *mods ));
LDAP_SLAPD_F( void ) slap_modlist_free LDAP_P(( LDAPModList *ml ));

LDAP_SLAPD_F( int ) slap_modlist2mods(
	LDAPModList *ml,
	int update,
	Modifications **mods,
	const char **text );

LDAP_SLAPD_F( int ) slap_mods_opattrs(
	Operation *op,
	Modifications **modlist,
	const char **text );

/*
 * module.c
 */

#ifdef SLAPD_MODULES

LDAP_SLAPD_F (int) module_init LDAP_P(( void ));
LDAP_SLAPD_F (int) module_kill LDAP_P(( void ));

LDAP_SLAPD_F (int) load_null_module(
	const void *module, const char *file_name);
LDAP_SLAPD_F (int) load_extop_module(
	const void *module, const char *file_name);

LDAP_SLAPD_F (int) module_load LDAP_P((
	const char* file_name,
	int argc, char *argv[] ));
LDAP_SLAPD_F (int) module_path LDAP_P(( const char* path ));

LDAP_SLAPD_F (void) *module_resolve LDAP_P((
	const void *module, const char *name));

#endif /* SLAPD_MODULES */

/*
 * monitor.c
 */
LDAP_SLAPD_F (char *) supportedControls[];

LDAP_SLAPD_F (int) monitor_info LDAP_P((
	Entry **entry, const char **text ));

/*
 * operation.c
 */

LDAP_SLAPD_F (void) slap_op_free LDAP_P(( Operation *op ));
LDAP_SLAPD_F (Operation *) slap_op_alloc LDAP_P((
	BerElement *ber, ber_int_t msgid,
	ber_tag_t tag, ber_int_t id ));

LDAP_SLAPD_F (int) slap_op_add LDAP_P(( Operation **olist, Operation *op ));
LDAP_SLAPD_F (int) slap_op_remove LDAP_P(( Operation **olist, Operation *op ));
LDAP_SLAPD_F (Operation *) slap_op_pop LDAP_P(( Operation **olist ));

/*
 * phonetic.c
 */

LDAP_SLAPD_F (char *) first_word LDAP_P(( char *s ));
LDAP_SLAPD_F (char *) next_word LDAP_P(( char *s ));
LDAP_SLAPD_F (char *) word_dup LDAP_P(( char *w ));
LDAP_SLAPD_F (char *) phonetic LDAP_P(( char *s ));

/*
 * repl.c
 */

LDAP_SLAPD_F (void) replog LDAP_P(( Backend *be, Operation *op, char *dn, void *change ));

/*
 * result.c
 */

LDAP_SLAPD_F (struct berval **) get_entry_referrals LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e ));

LDAP_SLAPD_F (void) send_ldap_result LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls ));

LDAP_SLAPD_F (void) send_ldap_sasl LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched,
	const char *text,
	struct berval **refs,
	LDAPControl **ctrls,
	struct berval *cred ));

LDAP_SLAPD_F (void) send_ldap_disconnect LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *text ));

LDAP_SLAPD_F (void) send_ldap_extended LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched,
	const char *text, struct berval **refs,
	const char *rspoid, struct berval *rspdata,
	LDAPControl **ctrls ));

LDAP_SLAPD_F (void) send_ldap_partial LDAP_P((
	Connection *conn, Operation *op,
	const char *rspoid, struct berval *rspdata,
	LDAPControl **ctrls ));

LDAP_SLAPD_F (void) send_search_result LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls,
	int nentries ));

LDAP_SLAPD_F (int) send_search_reference LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, struct berval **refs, int scope,
	LDAPControl **ctrls,
	struct berval ***v2refs ));

LDAP_SLAPD_F (int) send_search_entry LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, char **attrs, int attrsonly,
	LDAPControl **ctrls ));

LDAP_SLAPD_F (int) str2result LDAP_P(( char *s,
	int *code, char **matched, char **info ));

/*
 * sasl.c
 */

LDAP_SLAPD_F (int) slap_sasl_init(void);
LDAP_SLAPD_F (char *) slap_sasl_secprops( const char * );
LDAP_SLAPD_F (int) slap_sasl_destroy(void);

LDAP_SLAPD_F (int) slap_sasl_open( Connection *c );
LDAP_SLAPD_F (char **) slap_sasl_mechs( Connection *c );

LDAP_SLAPD_F (int) slap_sasl_external( Connection *c,
	slap_ssf_t ssf,	/* relative strength of external security */
	char *authid );	/* asserted authenication id */

LDAP_SLAPD_F (int) slap_sasl_reset( Connection *c );
LDAP_SLAPD_F (int) slap_sasl_close( Connection *c );

LDAP_SLAPD_F (int) slap_sasl_bind LDAP_P((
	Connection *conn, Operation *op, 
	const char *dn, const char *ndn,
	const char *mech, struct berval *cred,
	char **edn, slap_ssf_t *ssf ));

/* oc.c */
LDAP_SLAPD_F (int) oc_schema_info( Entry *e );

/* mr.c */
LDAP_SLAPD_F (int) mr_schema_info( Entry *e );

/* syntax.c */
LDAP_SLAPD_F (int) syn_schema_info( Entry *e );

/*
 * schema.c
 */

LDAP_SLAPD_F (ObjectClass *) oc_find LDAP_P((
	const char *ocname));

LDAP_SLAPD_F (int) oc_add LDAP_P((
	LDAPObjectClass *oc,
	const char **err));

LDAP_SLAPD_F (int) is_object_subclass LDAP_P((
	ObjectClass *sub,
	ObjectClass *sup ));


LDAP_SLAPD_F (Syntax *) syn_find LDAP_P((const char *synname));
LDAP_SLAPD_F (Syntax *) syn_find_desc LDAP_P((const char *syndesc, int *slen));
#ifdef SLAPD_BINARY_CONVERSION
LDAP_SLAPD_F (int) syn_add LDAP_P((
	LDAPSyntax *syn,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *normalize,
	slap_syntax_transform_func *pretty,
	slap_syntax_transform_func *ber2str,
	slap_syntax_transform_func *str2ber,
	const char **err));
#else
LDAP_SLAPD_F (int) syn_add LDAP_P((
	LDAPSyntax *syn,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *normalize,
	slap_syntax_transform_func *pretty,
	const char **err));
#endif

LDAP_SLAPD_F (MatchingRule *) mr_find LDAP_P((const char *mrname));
LDAP_SLAPD_F (int) mr_add LDAP_P((LDAPMatchingRule *mr,
	unsigned usage,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
	slap_mr_match_func *match,
	slap_mr_indexer_func *indexer,
	slap_mr_filter_func *filter,
	MatchingRule * associated,
	const char **err));

LDAP_SLAPD_F (int) register_syntax LDAP_P((
	char *desc,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *ber2str,
	slap_syntax_transform_func *str2ber ));

LDAP_SLAPD_F (int) register_matching_rule LDAP_P((
	char * desc,
	unsigned usage,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
	slap_mr_match_func *match,
	slap_mr_indexer_func *indexer,
	slap_mr_filter_func *filter,
	const char *associated ));

LDAP_SLAPD_F (int) schema_info LDAP_P(( Entry **entry, const char **text ));

LDAP_SLAPD_F (int) is_entry_objectclass LDAP_P((
	Entry *, ObjectClass *oc ));
#define is_entry_alias(e)		is_entry_objectclass((e), slap_schema.si_oc_alias)
#define is_entry_referral(e)	is_entry_objectclass((e), slap_schema.si_oc_referral)


/*
 * schema_check.c
 */
int oc_check_allowed(
	AttributeType *type,
	struct berval **oclist );
LDAP_SLAPD_F (int) entry_schema_check LDAP_P((
	Entry *e, Attribute *attrs,
	const char** text ));


/*
 * schema_init.c
 */
LDAP_SLAPD_F (int) schema_init LDAP_P((void));
LDAP_SLAPD_F (int) schema_prep LDAP_P((void));


/*
 * schemaparse.c
 */

LDAP_SLAPD_F (void) parse_oc_old LDAP_P(( Backend *be, const char *fname, int lineno, int argc, char **argv ));
LDAP_SLAPD_F (void) parse_oc LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
LDAP_SLAPD_F (void) parse_at LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
LDAP_SLAPD_F (void) parse_oidm LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
LDAP_SLAPD_F (char *) scherr2str LDAP_P((int code)) LDAP_GCCATTR((const));
LDAP_SLAPD_F (int) dscompare LDAP_P(( const char *s1, const char *s2del, char delim ));


/*
 * starttls.c
 */

LDAP_SLAPD_F (int) starttls_extop LDAP_P((
	Connection *conn, Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl ***rspctrls,
	const char ** text,
	struct berval *** refs ));


/*
 * str2filter.c
 */

LDAP_SLAPD_F (Filter *) str2filter LDAP_P(( const char *str ));

/*
 * suffixalias.c
 */
LDAP_SLAPD_F (char *) suffix_alias LDAP_P(( Backend *be, char *ndn ));

/*
 * value.c
 */
LDAP_SLAPD_F (int) value_normalize LDAP_P((
	AttributeDescription *ad,
	unsigned usage,
	struct berval *in,
	struct berval **out,
	const char ** text ));
LDAP_SLAPD_F (int) value_match LDAP_P((
	int *match,
	AttributeDescription *ad,
	MatchingRule *mr,
	unsigned flags,
	struct berval *v1,
	void *v2,
	const char ** text ));
LDAP_SLAPD_F (int) value_find LDAP_P((
	AttributeDescription *ad,
	struct berval **values,
	struct berval *value ));
LDAP_SLAPD_F (int) value_add LDAP_P(( struct berval ***vals, struct berval **addvals ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
LDAP_SLAPD_F (void) slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

/*
 * passwd.c
 */
LDAP_SLAPD_F (int) passwd_extop LDAP_P((
	Connection *conn, Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl *** rspctrls,
	const char ** text,
	struct berval *** refs ));

LDAP_SLAPD_F (int) slap_passwd_check(
	Attribute			*attr,
	struct berval		*cred );

LDAP_SLAPD_F (struct berval *) slap_passwd_generate( void );

LDAP_SLAPD_F (struct berval *) slap_passwd_hash(
	struct berval		*cred );

LDAP_SLAPD_F (struct berval *) slap_passwd_return(
	struct berval		*cred );

LDAP_SLAPD_F (int) slap_passwd_parse(
	struct berval *reqdata,
	struct berval **id,
	struct berval **oldpass,
	struct berval **newpass,
	const char **text );

/*
 * kerberos.c
 */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
extern char		*ldap_srvtab;
LDAP_SLAPD_F (int)	krbv4_ldap_auth();
#endif

/*
 * Other...
 */

LDAP_SLAPD_F (struct berval **)	default_referral;
LDAP_SLAPD_F (char *)		replogfile;
LDAP_SLAPD_F (const char) 	Versionstr[];
LDAP_SLAPD_F (int)		defsize;
LDAP_SLAPD_F (int)		deftime;
LDAP_SLAPD_F (int)		g_argc;
LDAP_SLAPD_F (slap_access_t)	global_default_access;
LDAP_SLAPD_F (int)		global_readonly;
LDAP_SLAPD_F (int)		global_lastmod;
LDAP_SLAPD_F (int)		global_idletimeout;
LDAP_SLAPD_F (int)		global_schemacheck;
LDAP_SLAPD_F (char)		*global_realm;
LDAP_SLAPD_F (char)		*default_passwd_hash;
LDAP_SLAPD_F (int)		lber_debug;
LDAP_SLAPD_F (int)		ldap_syslog;

LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	num_sent_mutex;
LDAP_SLAPD_F (long)		num_bytes_sent;
LDAP_SLAPD_F (long)		num_pdu_sent;
LDAP_SLAPD_F (long)		num_entries_sent;
LDAP_SLAPD_F (long)		num_refs_sent;

LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	num_ops_mutex;
LDAP_SLAPD_F (long)		num_ops_completed;
LDAP_SLAPD_F (long)		num_ops_initiated;

LDAP_SLAPD_F (char *)		slapd_pid_file;
LDAP_SLAPD_F (char *)		slapd_args_file;
LDAP_SLAPD_F (char)		**g_argv;
LDAP_SLAPD_F (time_t)		starttime;

LDAP_SLAPD_F (time_t) slap_get_time LDAP_P((void));

LDAP_SLAPD_F (ldap_pvt_thread_pool_t)	connection_pool;

LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	entry2str_mutex;
LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	replog_mutex;

#ifdef SLAPD_CRYPT
LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	crypt_mutex;
#endif
LDAP_SLAPD_F (ldap_pvt_thread_mutex_t)	gmtime_mutex;

LDAP_SLAPD_F (AccessControl *) global_acl;

LDAP_SLAPD_F (int)	slap_init LDAP_P((int mode, const char* name));
LDAP_SLAPD_F (int)	slap_startup LDAP_P(( Backend *be ));
LDAP_SLAPD_F (int)	slap_shutdown LDAP_P(( Backend *be ));
LDAP_SLAPD_F (int)	slap_destroy LDAP_P((void));

struct sockaddr_in;

LDAP_SLAPD_F (int) slapd_daemon_init( const char *urls );
LDAP_SLAPD_F (int) slapd_daemon_destroy(void);
LDAP_SLAPD_F (int) slapd_daemon(void);

LDAP_SLAPD_F (void) slapd_set_write LDAP_P((ber_socket_t s, int wake));
LDAP_SLAPD_F (void) slapd_clr_write LDAP_P((ber_socket_t s, int wake));
LDAP_SLAPD_F (void) slapd_set_read LDAP_P((ber_socket_t s, int wake));
LDAP_SLAPD_F (void) slapd_clr_read LDAP_P((ber_socket_t s, int wake));

LDAP_SLAPD_F (void) slapd_remove LDAP_P((ber_socket_t s, int wake));

LDAP_SLAPD_F (RETSIGTYPE) slap_sig_shutdown LDAP_P((int sig));
LDAP_SLAPD_F (RETSIGTYPE) slap_sig_wake LDAP_P((int sig));

LDAP_SLAPD_F (int) config_info LDAP_P((
	Entry **e, const char **text ));

LDAP_SLAPD_F (int) root_dse_info LDAP_P((
	Connection *conn,
	Entry **e,
	const char **text ));

LDAP_SLAPD_F (int) do_abandon LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_add LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_bind LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_compare LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_delete LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_modify LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_modrdn LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_search LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_unbind LDAP_P((Connection *conn, Operation *op));
LDAP_SLAPD_F (int) do_extended LDAP_P((Connection *conn, Operation *op));


LDAP_SLAPD_F (ber_socket_t) dtblsize;

LDAP_END_DECL

#endif /* _proto_slap */


/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _PROTO_SLAP
#define _PROTO_SLAP

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

LIBSLAPD_F( int ) schema_init_done;
LIBSLAPD_F( struct slap_internal_schema ) slap_schema;

LIBSLAPD_F (int) slap_str2ad LDAP_P((
	const char *,
	AttributeDescription **ad,
	const char **text ));

LIBSLAPD_F (int) slap_bv2ad LDAP_P((
	struct berval *bv,
	AttributeDescription **ad,
	const char **text ));

LIBSLAPD_F (AttributeDescription *) ad_dup LDAP_P((
	AttributeDescription *desc ));

LIBSLAPD_F (void) ad_free LDAP_P((
	AttributeDescription *desc,
	int freeit ));

#define ad_cmp(l,r)	( strcasecmp( \
	(l)->ad_cname->bv_val, (r)->ad_cname->bv_val ))

LIBSLAPD_F (int) is_ad_subtype LDAP_P((
	AttributeDescription *sub,
	AttributeDescription *super ));

LIBSLAPD_F (int) ad_inlist LDAP_P((
	AttributeDescription *desc,
	char **attrs ));

/*
 * acl.c
 */

LIBSLAPD_F (int) access_allowed LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, AttributeDescription *desc, struct berval *val,
	slap_access_t access ));
LIBSLAPD_F (int) acl_check_modlist LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, Modifications *ml ));

LIBSLAPD_F (void) acl_append( AccessControl **l, AccessControl *a );

/*
 * aclparse.c
 */

LIBSLAPD_F (void) parse_acl LDAP_P(( Backend *be,
	const char *fname, int lineno,
	int argc, char **argv ));

LIBSLAPD_F (char *) access2str LDAP_P(( slap_access_t access ));
LIBSLAPD_F (slap_access_t) str2access LDAP_P(( const char *str ));

#define ACCESSMASK_MAXLEN	sizeof("unknown (+wrscan)")
LIBSLAPD_F (char *) accessmask2str LDAP_P(( slap_access_mask_t mask, char* ));
LIBSLAPD_F (slap_access_mask_t) str2accessmask LDAP_P(( const char *str ));

/*
 * at.c
 */

LIBSLAPD_F (void) at_config LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
LIBSLAPD_F (AttributeType *) at_find LDAP_P(( const char *name ));
LIBSLAPD_F (int) at_find_in_list LDAP_P(( AttributeType *sat, AttributeType **list ));
LIBSLAPD_F (int) at_append_to_list LDAP_P(( AttributeType *sat, AttributeType ***listp ));
LIBSLAPD_F (int) at_delete_from_list LDAP_P(( int pos, AttributeType ***listp ));
LIBSLAPD_F (int) at_schema_info LDAP_P(( Entry *e ));
LIBSLAPD_F (int) at_add LDAP_P(( LDAP_ATTRIBUTE_TYPE *at, const char **err ));

LIBSLAPD_F (int) is_at_subtype LDAP_P((
	AttributeType *sub,
	AttributeType *super ));

LIBSLAPD_F (int) is_at_syntax LDAP_P((
	AttributeType *at,
	const char *oid ));

#	define at_canonical_name(at) ((at)->sat_cname)	


/*
 * attr.c
 */

LIBSLAPD_F (void) attr_free LDAP_P(( Attribute *a ));
LIBSLAPD_F (Attribute *) attr_dup LDAP_P(( Attribute *a ));

LIBSLAPD_F (int) attr_merge LDAP_P(( Entry *e,
	AttributeDescription *desc,
	struct berval **vals ));
LIBSLAPD_F (Attribute *) attrs_find LDAP_P(( Attribute *a, AttributeDescription *desc ));
LIBSLAPD_F (Attribute *) attr_find LDAP_P(( Attribute *a, AttributeDescription *desc ));
LIBSLAPD_F (int) attr_delete LDAP_P(( Attribute **attrs, AttributeDescription *desc ));

LIBSLAPD_F (void) attrs_free LDAP_P(( Attribute *a ));
LIBSLAPD_F (Attribute *) attrs_dup LDAP_P(( Attribute *a ));


/*
 * ava.c
 */
LIBSLAPD_F (int) get_ava LDAP_P((
	BerElement *ber,
	AttributeAssertion **ava,
	unsigned usage,
	const char **text ));
LIBSLAPD_F (void) ava_free LDAP_P((
	AttributeAssertion *ava,
	int freeit ));

/*
 * backend.c
 */

LIBSLAPD_F (int) backend_init LDAP_P((void));
LIBSLAPD_F (int) backend_add LDAP_P((BackendInfo *aBackendInfo));
LIBSLAPD_F (int) backend_num LDAP_P((Backend *be));
LIBSLAPD_F (int) backend_startup LDAP_P((Backend *be));
LIBSLAPD_F (int) backend_shutdown LDAP_P((Backend *be));
LIBSLAPD_F (int) backend_destroy LDAP_P((void));

LIBSLAPD_F (BackendInfo *) backend_info LDAP_P(( const char *type ));
LIBSLAPD_F (BackendDB *) backend_db_init LDAP_P(( const char *type ));

LIBSLAPD_F (BackendDB *) select_backend LDAP_P(( const char * dn ));

LIBSLAPD_F (int) be_issuffix LDAP_P(( Backend *be, const char *suffix ));
LIBSLAPD_F (int) be_isroot LDAP_P(( Backend *be, const char *ndn ));
LIBSLAPD_F (int) be_isroot_pw LDAP_P(( Backend *be, const char *ndn, struct berval *cred ));
LIBSLAPD_F (char *) be_root_dn LDAP_P(( Backend *be ));
LIBSLAPD_F (int) be_entry_release_rw LDAP_P(( Backend *be, Entry *e, int rw ));
#define be_entry_release_r( be, e ) be_entry_release_rw( be, e, 0 )
#define be_entry_release_w( be, e ) be_entry_release_rw( be, e, 1 )

LIBSLAPD_F (int) backend_unbind LDAP_P((Connection *conn, Operation *op));

LIBSLAPD_F( int )	backend_check_controls LDAP_P((
	Backend *be,
	Connection *conn,
	Operation *op,
	const char **text ));

LIBSLAPD_F (int) backend_connection_init LDAP_P((Connection *conn));
LIBSLAPD_F (int) backend_connection_destroy LDAP_P((Connection *conn));

LIBSLAPD_F (int) backend_group LDAP_P((Backend *be,
	Entry *target,
	const char *gr_ndn,
	const char *op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at
));

LIBSLAPD_F (Attribute *) backend_operational( Backend *, Entry * );



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
LIBSLAPD_F (void *) ch_malloc LDAP_P(( ber_len_t size ));
LIBSLAPD_F (void *) ch_realloc LDAP_P(( void *block, ber_len_t size ));
LIBSLAPD_F (void *) ch_calloc LDAP_P(( ber_len_t nelem, ber_len_t size ));
LIBSLAPD_F (char *) ch_strdup LDAP_P(( const char *string ));
LIBSLAPD_F (void) ch_free LDAP_P(( void * ));

#ifndef CH_FREE
#undef free
#define free ch_free
#endif
#endif

/*
 * charray.c
 */

LIBSLAPD_F (void) charray_add LDAP_P(( char ***a, const char *s ));
LIBSLAPD_F (void) charray_merge LDAP_P(( char ***a, char **s ));
LIBSLAPD_F (void) charray_free LDAP_P(( char **array ));
LIBSLAPD_F (int) charray_inlist LDAP_P(( char **a, const char *s ));
LIBSLAPD_F (char **) charray_dup LDAP_P(( char **a ));
LIBSLAPD_F (char **) str2charray LDAP_P(( const char *str, const char *brkstr ));

/*
 * controls.c
 */
LIBSLAPD_F (int) get_ctrls LDAP_P((
	Connection *co,
	Operation *op,
	int senderrors ));

LIBSLAPD_F (int) get_manageDSAit LDAP_P(( Operation *op ));

/*
 * config.c
 */

LIBSLAPD_F (int) read_config LDAP_P(( const char *fname ));


/*
 * index.c
 */
LIBSLAPD_F (int) slap_index2prefix LDAP_P(( int indextype ));
LIBSLAPD_F (int) slap_str2index LDAP_P(( const char *str, slap_index *idx ));

/*
 * connection.c
 */
LIBSLAPD_F (int) connections_init LDAP_P((void));
LIBSLAPD_F (int) connections_shutdown LDAP_P((void));
LIBSLAPD_F (int) connections_destroy LDAP_P((void));
LIBSLAPD_F (int) connections_timeout_idle LDAP_P((time_t));

LIBSLAPD_F (long) connection_init LDAP_P((
	ber_socket_t s,
	const char* url,
	const char* dnsname,
	const char* peername,
	const char* sockname,
	int use_tls ));

LIBSLAPD_F (void) connection_closing LDAP_P(( Connection *c ));
LIBSLAPD_F (int) connection_state_closing LDAP_P(( Connection *c ));
LIBSLAPD_F (const char *) connection_state2str LDAP_P(( int state )) LDAP_GCCATTR((const));

LIBSLAPD_F (int) connection_write LDAP_P((ber_socket_t s));
LIBSLAPD_F (int) connection_read LDAP_P((ber_socket_t s));

LIBSLAPD_F (unsigned long) connections_nextid(void);

LIBSLAPD_F (Connection *) connection_first LDAP_P((ber_socket_t *));
LIBSLAPD_F (Connection *) connection_next LDAP_P((Connection *, ber_socket_t *));
LIBSLAPD_F (void) connection_done LDAP_P((Connection *));

/*
 * dn.c
 */

LIBSLAPD_F (char *) dn_validate LDAP_P(( char *dn ));
LIBSLAPD_F (char *) dn_normalize LDAP_P(( char *dn ));
LIBSLAPD_F (char *) dn_parent LDAP_P(( Backend *be, const char *dn ));
LIBSLAPD_F (char **) dn_subtree LDAP_P(( Backend *be, const char *dn ));
LIBSLAPD_F (char *) dn_rdn LDAP_P(( Backend *be, const char *dn ));
LIBSLAPD_F (int) dn_issuffix LDAP_P(( const char *dn, const char *suffix ));
LIBSLAPD_F (int) rdn_validate LDAP_P(( const char* str ));
LIBSLAPD_F (char *) rdn_attr_value LDAP_P(( const char * rdn ));
LIBSLAPD_F (char *) rdn_attr_type LDAP_P(( const char * rdn ));

LIBSLAPD_F (void) build_new_dn LDAP_P(( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn ));
/*
 * entry.c
 */

LIBSLAPD_F (int) entry_destroy LDAP_P((void));

LIBSLAPD_F (Entry *) str2entry LDAP_P(( char	*s ));
LIBSLAPD_F (char *) entry2str LDAP_P(( Entry *e, int *len ));
LIBSLAPD_F (void) entry_free LDAP_P(( Entry *e ));

LIBSLAPD_F (int) entry_cmp LDAP_P(( Entry *a, Entry *b ));
LIBSLAPD_F (int) entry_dn_cmp LDAP_P(( Entry *a, Entry *b ));
LIBSLAPD_F (int) entry_id_cmp LDAP_P(( Entry *a, Entry *b ));

/*
 * extended.c
 */

#define SLAPD_EXTOP_GETVERSION 0
#define SLAPD_EXTOP_GETPROTO 1
#define SLAPD_EXTOP_GETAUTH 2
#define SLAPD_EXTOP_GETDN 3
#define SLAPD_EXTOP_GETCLIENT 4

typedef int (*SLAP_EXTOP_CALLBACK_FN) LDAP_P((
	Connection *conn, Operation *op,
	int msg, int arg, void *argp ));

typedef int (*SLAP_EXTOP_MAIN_FN) LDAP_P((
	SLAP_EXTOP_CALLBACK_FN,
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

LIBSLAPD_F (int) load_extension LDAP_P((const void *module, const char *file_name));
LIBSLAPD_F (char *) get_supported_extension LDAP_P((int index));

LIBSLAPD_F (int) load_extop LDAP_P((
	const char *ext_oid,
	SLAP_EXTOP_MAIN_FN ext_main ));

LIBSLAPD_F (int) extops_init LDAP_P(( void ));

LIBSLAPD_F (int) extops_kill LDAP_P(( void ));

LIBSLAPD_F (char *) get_supported_extop LDAP_P((int index));

/*
 * filter.c
 */

LIBSLAPD_F (int) get_filter LDAP_P((
	Connection *conn,
	BerElement *ber,
	Filter **filt,
	char **fstr,
	const char **text ));

LIBSLAPD_F (void) filter_free LDAP_P(( Filter *f ));
LIBSLAPD_F (void) filter_print LDAP_P(( Filter *f ));

/*
 * filterentry.c
 */

LIBSLAPD_F (int) test_filter LDAP_P((
	Backend *be, Connection *conn, Operation *op, Entry *e, Filter	*f ));

/*
 * lock.c
 */

LIBSLAPD_F (FILE *) lock_fopen LDAP_P(( const char *fname, const char *type, FILE **lfp ));
LIBSLAPD_F (int) lock_fclose LDAP_P(( FILE *fp, FILE *lfp ));


/*
 * modify.c
 *	should be relocated to separate file
 */
LIBSLAPD_F( void ) slap_mod_free LDAP_P(( Modification *mod, int freeit ));
LIBSLAPD_F( void ) slap_mods_free LDAP_P(( Modifications *mods ));
LIBSLAPD_F( void ) slap_modlist_free LDAP_P(( LDAPModList *ml ));

LIBSLAPD_F( int ) slap_modlist2mods(
	LDAPModList *ml,
	int update,
	Modifications **mods,
	const char **text );

LIBSLAPD_F( int ) slap_mods_opattrs(
	Operation *op,
	Modifications **modlist,
	const char **text );

/*
 * module.c
 */

#ifdef SLAPD_MODULES

LIBSLAPD_F (int) module_init LDAP_P(( void ));
LIBSLAPD_F (int) module_kill LDAP_P(( void ));

LIBSLAPD_F (int) load_null_module(
	const void *module, const char *file_name);
LIBSLAPD_F (int) load_extop_module(
	const void *module, const char *file_name);

LIBSLAPD_F (int) module_load LDAP_P((
	const char* file_name,
	int argc, char *argv[] ));
LIBSLAPD_F (int) module_path LDAP_P(( const char* path ));

LIBSLAPD_F (void) *module_resolve LDAP_P((
	const void *module, const char *name));

#endif /* SLAPD_MODULES */

/*
 * monitor.c
 */
LIBSLAPD_F (char *) supportedControls[];

LIBSLAPD_F (int) monitor_info LDAP_P((
	Entry **entry, const char **text ));

/*
 * operation.c
 */

LIBSLAPD_F (void) slap_op_free LDAP_P(( Operation *op ));
LIBSLAPD_F (Operation *) slap_op_alloc LDAP_P((
	BerElement *ber, ber_int_t msgid,
	ber_tag_t tag, ber_int_t id ));

LIBSLAPD_F (int) slap_op_add LDAP_P(( Operation **olist, Operation *op ));
LIBSLAPD_F (int) slap_op_remove LDAP_P(( Operation **olist, Operation *op ));
LIBSLAPD_F (Operation *) slap_op_pop LDAP_P(( Operation **olist ));

/*
 * phonetic.c
 */

LIBSLAPD_F (char *) first_word LDAP_P(( char *s ));
LIBSLAPD_F (char *) next_word LDAP_P(( char *s ));
LIBSLAPD_F (char *) word_dup LDAP_P(( char *w ));
LIBSLAPD_F (char *) phonetic LDAP_P(( char *s ));

/*
 * repl.c
 */

LIBSLAPD_F (void) replog LDAP_P(( Backend *be, Operation *op, char *dn, void *change ));

/*
 * result.c
 */

LIBSLAPD_F (struct berval **) get_entry_referrals LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e ));

LIBSLAPD_F (void) send_ldap_result LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls ));

LIBSLAPD_F (void) send_ldap_sasl LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched,
	const char *text,
	struct berval **refs,
	LDAPControl **ctrls,
	struct berval *cred ));

LIBSLAPD_F (void) send_ldap_disconnect LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *text ));

LIBSLAPD_F (void) send_ldap_extended LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched,
	const char *text, struct berval **refs,
	const char *rspoid, struct berval *rspdata,
	LDAPControl **ctrls ));

LIBSLAPD_F (void) send_ldap_partial LDAP_P((
	Connection *conn, Operation *op,
	const char *rspoid, struct berval *rspdata,
	LDAPControl **ctrls ));

LIBSLAPD_F (void) send_search_result LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched, const char *text,
	struct berval **refs,
	LDAPControl **ctrls,
	int nentries ));

LIBSLAPD_F (int) send_search_reference LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, struct berval **refs, int scope,
	LDAPControl **ctrls,
	struct berval ***v2refs ));

LIBSLAPD_F (int) send_search_entry LDAP_P((
	Backend *be, Connection *conn, Operation *op,
	Entry *e, char **attrs, int attrsonly,
	LDAPControl **ctrls ));

LIBSLAPD_F (int) str2result LDAP_P(( char *s,
	int *code, char **matched, char **info ));

/*
 * sasl.c
 */
LIBSLAPD_F (char **) supportedSASLMechanisms;

LIBSLAPD_F (int) sasl_init(void);
LIBSLAPD_F (int) sasl_destroy(void);
LIBSLAPD_F (int) sasl_errldap LDAP_P(( int ));
LIBSLAPD_F (int) sasl_bind LDAP_P((
	Connection *conn, Operation *op, 
	const char *dn, const char *ndn,
	const char *mech, struct berval *cred,
	char **edn ));

/* oc.c */
LIBSLAPD_F (int) oc_schema_info( Entry *e );

/* mr.c */
LIBSLAPD_F (int) mr_schema_info( Entry *e );

/* syntax.c */
LIBSLAPD_F (int) syn_schema_info( Entry *e );

/*
 * schema.c
 */

LIBSLAPD_F (ObjectClass *) oc_find LDAP_P((
	const char *ocname));

LIBSLAPD_F (int) oc_add LDAP_P((
	LDAP_OBJECT_CLASS *oc,
	const char **err));

LIBSLAPD_F (int) is_object_subclass LDAP_P((
	ObjectClass *sub,
	ObjectClass *sup ));


LIBSLAPD_F (Syntax *) syn_find LDAP_P((const char *synname));
LIBSLAPD_F (Syntax *) syn_find_desc LDAP_P((const char *syndesc, int *slen));
#ifdef SLAPD_BINARY_CONVERSION
LIBSLAPD_F (int) syn_add LDAP_P((
	LDAP_SYNTAX *syn,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *normalize,
	slap_syntax_transform_func *pretty,
	slap_syntax_transform_func *ber2str,
	slap_syntax_transform_func *str2ber,
	const char **err));
#else
LIBSLAPD_F (int) syn_add LDAP_P((
	LDAP_SYNTAX *syn,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *normalize,
	slap_syntax_transform_func *pretty,
	const char **err));
#endif

LIBSLAPD_F (MatchingRule *) mr_find LDAP_P((const char *mrname));
LIBSLAPD_F (int) mr_add LDAP_P((LDAP_MATCHING_RULE *mr,
	unsigned usage,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
	slap_mr_match_func *match,
	slap_mr_indexer_func *indexer,
	slap_mr_filter_func *filter,
	const char **err));

LIBSLAPD_F (int) register_syntax LDAP_P((
	char *desc,
	unsigned flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *ber2str,
	slap_syntax_transform_func *str2ber ));

LIBSLAPD_F (int) register_matching_rule LDAP_P((
	char * desc,
	unsigned usage,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
	slap_mr_match_func *match,
	slap_mr_indexer_func *indexer,
	slap_mr_filter_func *filter	));

LIBSLAPD_F (int) schema_info LDAP_P(( Entry **entry, const char **text ));

LIBSLAPD_F (int) is_entry_objectclass LDAP_P((
	Entry *, ObjectClass *oc ));
#define is_entry_alias(e)		is_entry_objectclass((e), slap_schema.si_oc_alias)
#define is_entry_referral(e)	is_entry_objectclass((e), slap_schema.si_oc_referral)


/*
 * schema_check.c
 */
int oc_check_allowed(
	AttributeType *type,
	struct berval **oclist );
LIBSLAPD_F (int) entry_schema_check LDAP_P((
	Entry *e, Attribute *attrs,
	const char** text ));


/*
 * schema_init.c
 */
LIBSLAPD_F (int) schema_init LDAP_P((void));
LIBSLAPD_F (int) schema_prep LDAP_P((void));


/*
 * schemaparse.c
 */

LIBSLAPD_F (void) parse_oc_old LDAP_P(( Backend *be, const char *fname, int lineno, int argc, char **argv ));
LIBSLAPD_F (void) parse_oc LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
LIBSLAPD_F (void) parse_at LDAP_P(( const char *fname, int lineno, char *line, char **argv ));
LIBSLAPD_F (void) parse_oidm LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
LIBSLAPD_F (char *) scherr2str LDAP_P((int code)) LDAP_GCCATTR((const));
LIBSLAPD_F (int) dscompare LDAP_P(( const char *s1, const char *s2del, char delim ));


/*
 * starttls.c
 */

LIBSLAPD_F (int) starttls_extop LDAP_P((
	SLAP_EXTOP_CALLBACK_FN,
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

LIBSLAPD_F (Filter *) str2filter LDAP_P(( const char *str ));

/*
 * suffixalias.c
 */
LIBSLAPD_F (char *) suffix_alias LDAP_P(( Backend *be, char *ndn ));

/*
 * value.c
 */
LIBSLAPD_F (int) value_normalize LDAP_P((
	AttributeDescription *ad,
	unsigned usage,
	struct berval *in,
	struct berval **out,
	const char ** text ));
LIBSLAPD_F (int) value_match LDAP_P((
	int *match,
	AttributeDescription *ad,
	MatchingRule *mr,
	struct berval *v1,
	void *v2,
	const char ** text ));
LIBSLAPD_F (int) value_find LDAP_P((
	AttributeDescription *ad,
	struct berval **values,
	struct berval *value ));
LIBSLAPD_F (int) value_add LDAP_P(( struct berval ***vals, struct berval **addvals ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
LIBSLAPD_F (void) slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

/*
 * passwd.c
 */
LIBSLAPD_F (int) passwd_extop LDAP_P((
	SLAP_EXTOP_CALLBACK_FN,
	Connection *conn, Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl *** rspctrls,
	const char ** text,
	struct berval *** refs ));

LIBSLAPD_F (int) slap_passwd_check(
	Attribute			*attr,
	struct berval		*cred );

LIBSLAPD_F (struct berval *) slap_passwd_generate( void );

LIBSLAPD_F (struct berval *) slap_passwd_hash(
	struct berval		*cred );

LIBSLAPD_F (struct berval *) slap_passwd_return(
	struct berval		*cred );

LIBSLAPD_F (int) slap_passwd_parse(
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
LIBSLAPD_F (int)	krbv4_ldap_auth();
#endif

/*
 * Other...
 */

LIBSLAPD_F (struct berval **)	default_referral;
LIBSLAPD_F (char *)		replogfile;
LIBSLAPD_F (const char) 	Versionstr[];
LIBSLAPD_F (int)		active_threads;
LIBSLAPD_F (int)		defsize;
LIBSLAPD_F (int)		deftime;
LIBSLAPD_F (int)		g_argc;
LIBSLAPD_F (slap_access_t)	global_default_access;
LIBSLAPD_F (int)		global_readonly;
LIBSLAPD_F (int)		global_lastmod;
LIBSLAPD_F (int)		global_idletimeout;
LIBSLAPD_F (int)		global_schemacheck;
LIBSLAPD_F (char)		*global_realm;
LIBSLAPD_F (char)		*default_passwd_hash;
LIBSLAPD_F (int)		lber_debug;
LIBSLAPD_F (int)		ldap_syslog;

LIBSLAPD_F (ldap_pvt_thread_mutex_t)	num_sent_mutex;
LIBSLAPD_F (long)		num_bytes_sent;
LIBSLAPD_F (long)		num_pdu_sent;
LIBSLAPD_F (long)		num_entries_sent;
LIBSLAPD_F (long)		num_refs_sent;

LIBSLAPD_F (ldap_pvt_thread_mutex_t)	num_ops_mutex;
LIBSLAPD_F (long)		num_ops_completed;
LIBSLAPD_F (long)		num_ops_initiated;

LIBSLAPD_F (char *)		slapd_pid_file;
LIBSLAPD_F (char *)		slapd_args_file;
LIBSLAPD_F (char)		**g_argv;
LIBSLAPD_F (time_t)		starttime;

LIBSLAPD_F (time_t) slap_get_time LDAP_P((void));

LIBSLAPD_F (ldap_pvt_thread_mutex_t)	active_threads_mutex;
LIBSLAPD_F (ldap_pvt_thread_cond_t)	active_threads_cond;
LIBSLAPD_F (ldap_pvt_thread_pool_t)	connection_pool;

LIBSLAPD_F (ldap_pvt_thread_mutex_t)	entry2str_mutex;
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	replog_mutex;

#ifdef SLAPD_CRYPT
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	crypt_mutex;
#endif
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	gmtime_mutex;

LIBSLAPD_F (AccessControl *) global_acl;

LIBSLAPD_F (int)	slap_init LDAP_P((int mode, const char* name));
LIBSLAPD_F (int)	slap_startup LDAP_P(( Backend *be ));
LIBSLAPD_F (int)	slap_shutdown LDAP_P(( Backend *be ));
LIBSLAPD_F (int)	slap_destroy LDAP_P((void));

struct sockaddr_in;

LIBSLAPD_F (int) slapd_daemon_init( const char *urls );
LIBSLAPD_F (int) slapd_daemon_destroy(void);
LIBSLAPD_F (int) slapd_daemon(void);

LIBSLAPD_F (void) slapd_set_write LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_clr_write LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_set_read LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_clr_read LDAP_P((ber_socket_t s, int wake));

LIBSLAPD_F (void) slapd_remove LDAP_P((ber_socket_t s, int wake));

LIBSLAPD_F (RETSIGTYPE) slap_sig_shutdown LDAP_P((int sig));
LIBSLAPD_F (RETSIGTYPE) slap_sig_wake LDAP_P((int sig));

LIBSLAPD_F (int) config_info LDAP_P((
	Entry **e, const char **text ));

LIBSLAPD_F (int) root_dse_info LDAP_P((
	Entry **e, const char **text ));

LIBSLAPD_F (int) do_abandon LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_add LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_bind LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_compare LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_delete LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_modify LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_modrdn LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_search LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_unbind LDAP_P((Connection *conn, Operation *op));
LIBSLAPD_F (int) do_extended LDAP_P((Connection *conn, Operation *op));


LIBSLAPD_F (ber_socket_t) dtblsize;

LDAP_END_DECL

#endif /* _proto_slap */


/* $OpenLDAP$ */
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

LIBSLAPD_F (int) access_allowed LDAP_P(( Backend *be, Connection *conn,
	Operation *op, Entry *e,
	char *attr, struct berval *val, slap_access_t access ));

LIBSLAPD_F (int) acl_check_modlist LDAP_P(( Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	LDAPModList *ml ));

LIBSLAPD_F (void) acl_append( AccessControl **l, AccessControl *a );

LIBSLAPD_F (char *) get_supported_acimech LDAP_P((int index));

/*
 * aclparse.c
 */

LIBSLAPD_F (void) parse_acl LDAP_P(( Backend *be,
	const char *fname,
	int lineno,
	int argc, char **argv ));

LIBSLAPD_F (char *) access2str LDAP_P(( slap_access_t access ));
LIBSLAPD_F (slap_access_t) str2access LDAP_P(( const char *str ));

#define ACCESSMASK_MAXLEN	sizeof("unknown (+wrscan)")
LIBSLAPD_F (char *) accessmask2str LDAP_P(( slap_access_mask_t mask, char* ));
LIBSLAPD_F (slap_access_mask_t) str2accessmask LDAP_P(( const char *str ));

/*
 * attr.c
 */

LIBSLAPD_F (void) attr_free LDAP_P(( Attribute *a ));
LIBSLAPD_F (Attribute *) attr_dup LDAP_P(( Attribute *a ));
LIBSLAPD_F (char *) attr_normalize LDAP_P(( char *s ));
LIBSLAPD_F (int) attr_merge_fast LDAP_P(( Entry *e, char *type, struct berval **vals, int  nvals, int  naddvals, int  *maxvals, Attribute ***a ));
LIBSLAPD_F (int) attr_merge LDAP_P(( Entry *e, char *type, struct berval **vals ));
LIBSLAPD_F (Attribute *) attr_find LDAP_P(( Attribute *a, const char *type ));
LIBSLAPD_F (int) attr_delete LDAP_P(( Attribute **attrs, const char *type ));
LIBSLAPD_F (int) attr_syntax LDAP_P(( char *type ));
LIBSLAPD_F (void) attr_syntax_config LDAP_P(( const char *fname, int lineno, int argc, char **argv ));
LIBSLAPD_F (AttributeType *) at_find LDAP_P(( const char *name ));
LIBSLAPD_F (int) at_find_in_list LDAP_P(( AttributeType *sat, AttributeType **list ));
LIBSLAPD_F (int) at_append_to_list LDAP_P(( AttributeType *sat, AttributeType ***listp ));
LIBSLAPD_F (int) at_delete_from_list LDAP_P(( int pos, AttributeType ***listp ));
LIBSLAPD_F (int) at_fake_if_needed LDAP_P(( char *name ));
LIBSLAPD_F (int) at_schema_info LDAP_P(( Entry *e ));
LIBSLAPD_F (int) at_add LDAP_P(( LDAP_ATTRIBUTE_TYPE *at, const char **err ));
LIBSLAPD_F (char *) at_canonical_name LDAP_P(( char * a_type ));

LIBSLAPD_F (void) attrs_free LDAP_P(( Attribute *a ));
LIBSLAPD_F (Attribute *) attrs_dup LDAP_P(( Attribute *a ));

/*
 * ava.c
 */

LIBSLAPD_F (int) get_ava LDAP_P(( BerElement *ber, Ava *ava ));
LIBSLAPD_F (void) ava_free LDAP_P(( Ava *ava, int freeit ));

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

LIBSLAPD_F (int) backend_connection_init LDAP_P((Connection *conn));
LIBSLAPD_F (int) backend_connection_destroy LDAP_P((Connection *conn));

LIBSLAPD_F (int) backend_group LDAP_P((Backend *be,
	Entry *target,
	const char *gr_ndn,
	const char *op_ndn,
	const char *objectclassValue,
	const char *groupattrName));

#ifdef SLAPD_SCHEMA_DN
/* temporary extern for temporary routine*/
LIBSLAPD_F (Attribute *) backend_subschemasubentry( Backend * );
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
LIBSLAPD_F (char *) charray2str LDAP_P(( char **a ));

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
LIBSLAPD_F (char *) dn_rdn LDAP_P(( Backend *be, char *dn ));
LIBSLAPD_F (int) dn_issuffix LDAP_P(( char *dn, char *suffix ));
#ifdef DNS_DN
LIBSLAPD_F (int) dn_type LDAP_P(( char *dn ));
#endif
LIBSLAPD_F (int) rdn_validate LDAP_P(( const char* str ));
LIBSLAPD_F (char *) rdn_attr_value LDAP_P(( char * rdn ));
LIBSLAPD_F (char *) rdn_attr_type LDAP_P(( char * rdn ));

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

LIBSLAPD_F (int) load_extension LDAP_P((const void *module, const char *file_name));
LIBSLAPD_F (char *) get_supported_extension LDAP_P((int index));

/*
 * filter.c
 */

LIBSLAPD_F (int) get_filter LDAP_P(( Connection *conn, BerElement *ber, Filter **filt, char **fstr ));
LIBSLAPD_F (void) filter_free LDAP_P(( Filter *f ));
LIBSLAPD_F (void) filter_print LDAP_P(( Filter *f ));

/*
 * filterentry.c
 */

LIBSLAPD_F (int) test_filter LDAP_P(( Backend *be, Connection *conn, Operation *op, Entry *e, Filter	*f ));

/*
 * lock.c
 */

LIBSLAPD_F (FILE *) lock_fopen LDAP_P(( const char *fname, const char *type, FILE **lfp ));
LIBSLAPD_F (int) lock_fclose LDAP_P(( FILE *fp, FILE *lfp ));

/*
 * module.c
 */

#ifdef SLAPD_MODULES
LIBSLAPD_F (int) module_init LDAP_P(( void ));
LIBSLAPD_F (int) module_kill LDAP_P(( void ));

LIBSLAPD_F (int) module_load LDAP_P(( const char* file_name, int argc, char *argv[] ));
LIBSLAPD_F (int) module_path LDAP_P(( const char* path ));

LIBSLAPD_F (void) *module_resolve LDAP_P((const void *module, const char *name));
#endif /* SLAPD_MODULES */

/*
 * monitor.c
 */
LIBSLAPD_F (char *) supportedControls[];

LIBSLAPD_F (void) monitor_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

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
	struct berval *cred ));

LIBSLAPD_F (void) send_ldap_disconnect LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *text ));

LIBSLAPD_F (void) send_ldap_extended LDAP_P((
	Connection *conn, Operation *op,
	ber_int_t err, const char *matched,
	const char *text,
	char *rspoid, struct berval *rspdata ));

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

/*
 * schema.c
 */

LIBSLAPD_F (int) oc_schema_check LDAP_P(( Entry *e ));
LIBSLAPD_F (int) oc_check_operational_attr LDAP_P(( const char *type ));
LIBSLAPD_F (int) oc_check_usermod_attr LDAP_P(( const char *type ));
LIBSLAPD_F (int) oc_check_no_usermod_attr LDAP_P(( const char *type ));
LIBSLAPD_F (ObjectClass *) oc_find LDAP_P((const char *ocname));
LIBSLAPD_F (int) oc_add LDAP_P((LDAP_OBJECT_CLASS *oc, const char **err));
LIBSLAPD_F (Syntax *) syn_find LDAP_P((const char *synname));
LIBSLAPD_F (Syntax *) syn_find_desc LDAP_P((const char *syndesc, int *slen));
LIBSLAPD_F (int) syn_add LDAP_P((LDAP_SYNTAX *syn, slap_syntax_check_func *check, const char **err));
LIBSLAPD_F (MatchingRule *) mr_find LDAP_P((const char *mrname));
LIBSLAPD_F (int) mr_add LDAP_P((LDAP_MATCHING_RULE *mr, slap_mr_normalize_func *normalize, slap_mr_compare_func *compare, const char **err));
LIBSLAPD_F (int) case_ignore_normalize LDAP_P((struct berval *val, struct berval **normalized));
LIBSLAPD_F (int) register_syntax LDAP_P((char *desc,	slap_syntax_check_func *check ));
LIBSLAPD_F (int) register_matching_rule LDAP_P((char * desc,	slap_mr_normalize_func *normalize, slap_mr_compare_func *compare));
LIBSLAPD_F (void) schema_info LDAP_P((Connection *conn, Operation *op, char **attrs, int attrsonly));
LIBSLAPD_F (int) schema_init LDAP_P((void));

LIBSLAPD_F (int) is_entry_objectclass LDAP_P(( Entry *, const char* objectclass ));
#define is_entry_alias(e)		is_entry_objectclass((e), "ALIAS")
#define is_entry_referral(e)	is_entry_objectclass((e), "REFERRAL")


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
 * str2filter.c
 */

LIBSLAPD_F (Filter *) str2filter LDAP_P(( char *str ));

/*
 * suffixalias.c
 */
LIBSLAPD_F (char *) suffix_alias LDAP_P(( Backend *be, char *ndn ));

/*
 * value.c
 */

LIBSLAPD_F (int) value_add_fast LDAP_P(( struct berval ***vals, struct berval **addvals, int nvals, int naddvals, int *maxvals ));
LIBSLAPD_F (int) value_add LDAP_P(( struct berval ***vals, struct berval **addvals ));
LIBSLAPD_F (void) value_normalize LDAP_P(( char *s, int syntax ));
LIBSLAPD_F (int) value_cmp LDAP_P(( struct berval *v1, struct berval *v2, int syntax, int normalize ));
LIBSLAPD_F (int) value_find LDAP_P(( struct berval **vals, struct berval *v, int syntax, int normalize ));

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
LIBSLAPD_F (void) slap_init_user LDAP_P(( char *username, char *groupname ));
#endif

/*
 * passwd.c
 */
LIBSLAPD_F (int) slap_passwd_check(
	Attribute			*attr,
	struct berval		*cred );

/*
 * kerberos.c
 */
#ifdef HAVE_KERBEROS
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

LIBSLAPD_F (ldap_pvt_thread_mutex_t)	entry2str_mutex;
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	replog_mutex;

#ifdef SLAPD_CRYPT
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	crypt_mutex;
#endif
LIBSLAPD_F (ldap_pvt_thread_mutex_t)	gmtime_mutex;

LIBSLAPD_F (AccessControl *) global_acl;

LIBSLAPD_F (int)	slap_init LDAP_P((int mode, char* name));
LIBSLAPD_F (int)	slap_startup LDAP_P(( Backend *be ));
LIBSLAPD_F (int)	slap_shutdown LDAP_P(( Backend *be ));
LIBSLAPD_F (int)	slap_destroy LDAP_P((void));

struct sockaddr_in;

LIBSLAPD_F (int) slapd_daemon_init( char *urls, int port, int tls_port );
LIBSLAPD_F (int) slapd_daemon_destroy(void);
LIBSLAPD_F (int) slapd_daemon(void);

LIBSLAPD_F (void) slapd_set_write LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_clr_write LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_set_read LDAP_P((ber_socket_t s, int wake));
LIBSLAPD_F (void) slapd_clr_read LDAP_P((ber_socket_t s, int wake));

LIBSLAPD_F (void) slapd_remove LDAP_P((ber_socket_t s, int wake));

LIBSLAPD_F (RETSIGTYPE) slap_sig_shutdown LDAP_P((int sig));
LIBSLAPD_F (RETSIGTYPE) slap_sig_wake LDAP_P((int sig));

LIBSLAPD_F (void) config_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

LIBSLAPD_F (void) root_dse_info LDAP_P((
	Connection *conn,
	Operation *op,
	char ** attrs,
	int attrsonly ));

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


/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2004 The OpenLDAP Foundation.
 * Portions Copyright 1997,2002-2003 IBM Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by IBM Corporation for use in
 * IBM products and subsequently ported to OpenLDAP Software by
 * Steve Omrani.  Additional significant contributors include:
 *   Luke Howard
 */

#ifndef _PROTO_SLAPI_H
#define _PROTO_SLAPI_H

LDAP_BEGIN_DECL

/*
 * Was: slapi_utils.h
 */

extern int slapi_log_error( int severity, char *subsystem, char *fmt, ... );
extern Slapi_Entry *slapi_str2entry( char *s, int flags );
extern char *slapi_entry2str( Slapi_Entry *e, int *len );
extern int slapi_entry_attr_merge( Slapi_Entry *e, char *type, struct berval **vals );
extern int slapi_entry_attr_find( Slapi_Entry *e, char *type, Slapi_Attr **attr );
extern char *slapi_entry_attr_get_charptr( const Slapi_Entry *e, const char *type );
extern int slapi_entry_attr_delete( Slapi_Entry *e, char *type );
extern int slapi_entry_attr_get_int( const Slapi_Entry *e, const char *type );
extern int slapi_entry_attr_get_long( const Slapi_Entry *e, const char *type );
extern int slapi_entry_attr_get_uint( const Slapi_Entry *e, const char *type );
extern int slapi_entry_attr_get_ulong( const Slapi_Entry *e, const char *type );
extern int slapi_entry_attr_hasvalue( Slapi_Entry *e, const char *type, const char *value );
extern int slapi_entry_attr_merge_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern void slapi_entry_attr_set_charptr(Slapi_Entry* e, const char *type, const char *value);
extern void slapi_entry_attr_set_int( Slapi_Entry* e, const char *type, int l);
extern void slapi_entry_attr_set_uint( Slapi_Entry* e, const char *type, unsigned int l);
extern void slapi_entry_attr_set_long(Slapi_Entry* e, const char *type, long l);
extern void slapi_entry_attr_set_ulong(Slapi_Entry* e, const char *type, unsigned long l);
extern int slapi_is_rootdse( const char *dn );
extern int slapi_entry_has_children(const Slapi_Entry *e);
size_t slapi_entry_size(Slapi_Entry *e);
extern int slapi_entry_attr_merge_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern int slapi_entry_add_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern int slapi_entry_add_valueset(Slapi_Entry *e, const char *type, Slapi_ValueSet *vs);
extern int slapi_entry_delete_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern int slapi_entry_merge_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern int slapi_entry_attr_replace_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
extern int slapi_entry_add_value(Slapi_Entry *e, const char *type, const Slapi_Value *value);
extern int slapi_entry_add_string(Slapi_Entry *e, const char *type, const char *value);
extern int slapi_entry_delete_string(Slapi_Entry *e, const char *type, const char *value);
extern int slapi_entry_first_attr( const Slapi_Entry *e, Slapi_Attr **attr );
extern int slapi_entry_next_attr( const Slapi_Entry *e, Slapi_Attr *prevattr, Slapi_Attr **attr );
extern const char *slapi_entry_get_uniqueid( const Slapi_Entry *e );
extern void slapi_entry_set_uniqueid( Slapi_Entry *e, char *uniqueid );
extern int slapi_entry_schema_check( Slapi_PBlock *pb, Slapi_Entry *e );
extern int slapi_entry_rdn_values_present( const Slapi_Entry *e );
extern int slapi_entry_add_rdn_values( Slapi_Entry *e );

extern char *slapi_entry_get_dn( Slapi_Entry *e );
extern int slapi_x_entry_get_id( Slapi_Entry *e );
extern void slapi_entry_set_dn( Slapi_Entry *e, char *dn );
extern Slapi_Entry *slapi_entry_dup( Slapi_Entry *e );
extern Slapi_Entry *slapi_entry_alloc();
extern void slapi_entry_free( Slapi_Entry *e );
extern int slapi_attr_get_values( Slapi_Attr *attr, struct berval ***vals );

/* DS 5.x SLAPI */
extern int slapi_access_allowed( Slapi_PBlock *pb, Slapi_Entry *e, char *attr, 
		struct berval *val, int access );
extern int slapi_acl_check_mods( Slapi_PBlock *pb, Slapi_Entry *e, LDAPMod **mods, 
		char **errbuf );
extern Slapi_Attr *slapi_attr_new( void );
extern Slapi_Attr *slapi_attr_init( Slapi_Attr *a, const char *type );
extern void slapi_attr_free( Slapi_Attr **a );
extern Slapi_Attr *slapi_attr_dup( const Slapi_Attr *attr );
extern int slapi_attr_add_value( Slapi_Attr *a, const Slapi_Value *v );
extern int slapi_attr_type2plugin( const char *type, void **pi );
extern int slapi_attr_get_type( const Slapi_Attr *attr, char **type );
extern int slapi_attr_get_oid_copy( const Slapi_Attr *attr, char **oidp );
extern int slapi_attr_get_flags( const Slapi_Attr *attr, unsigned long *flags );
extern int slapi_attr_flag_is_set( const Slapi_Attr *attr, unsigned long flag );
extern int slapi_attr_value_cmp( const Slapi_Attr *attr, const struct berval *v1,
		const struct berval *v2 );
extern int slapi_attr_value_find( const Slapi_Attr *a, struct berval *v );
#if 0
#define SLAPI_TYPE_CMP_EXACT	0
#define SLAPI_TYPE_CMP_BASE	1
#define SLAPI_TYPE_CMP_SUBTYPE	2
#endif
extern int slapi_attr_type_cmp( const char *t1, const char *t2, int opt );
extern int slapi_attr_types_equivalent( const char *t1, const char *t2 );
extern int slapi_attr_first_value( Slapi_Attr *a, Slapi_Value **v );
extern int slapi_attr_next_value( Slapi_Attr *a, int hint, Slapi_Value **v );
extern int slapi_attr_get_numvalues( const Slapi_Attr *a, int *numValues );
extern int slapi_attr_get_valueset( const Slapi_Attr *a, Slapi_ValueSet **vs );
extern int slapi_attr_get_bervals_copy( Slapi_Attr *a, struct berval ***vals );
extern char *slapi_attr_syntax_normalize( const char *s );

extern Slapi_Value *slapi_value_new( void );
extern Slapi_Value *slapi_value_new_berval(const struct berval *bval);
extern Slapi_Value *slapi_value_new_value(const Slapi_Value *v);
extern Slapi_Value *slapi_value_new_string(const char *s);
extern Slapi_Value *slapi_value_init(Slapi_Value *v);
extern Slapi_Value *slapi_value_init_berval(Slapi_Value *v, struct berval *bval);
extern Slapi_Value *slapi_value_init_string(Slapi_Value *v,const char *s);
extern Slapi_Value *slapi_value_dup(const Slapi_Value *v);
extern void slapi_value_free(Slapi_Value **value);
extern const struct berval *slapi_value_get_berval( const Slapi_Value *value );
extern Slapi_Value *slapi_value_set_berval( Slapi_Value *value, const struct berval *bval );
extern Slapi_Value *slapi_value_set_value( Slapi_Value *value, const Slapi_Value *vfrom);
extern Slapi_Value *slapi_value_set( Slapi_Value *value, void *val, unsigned long len);
extern int slapi_value_set_string(Slapi_Value *value, const char *strVal);
extern int slapi_value_set_int(Slapi_Value *value, int intVal);
extern const char*slapi_value_get_string(const Slapi_Value *value);
extern int slapi_value_get_int(const Slapi_Value *value); 
extern unsigned int slapi_value_get_uint(const Slapi_Value *value); 
extern long slapi_value_get_long(const Slapi_Value *value); 
extern unsigned long slapi_value_get_ulong(const Slapi_Value *value); 
extern size_t slapi_value_get_length(const Slapi_Value *value);
extern int slapi_value_compare(const Slapi_Attr *a,const Slapi_Value *v1,const Slapi_Value *v2);

extern Slapi_ValueSet *slapi_valueset_new( void );
extern void slapi_valueset_free(Slapi_ValueSet *vs);
extern void slapi_valueset_init(Slapi_ValueSet *vs);
extern void slapi_valueset_done(Slapi_ValueSet *vs);
extern void slapi_valueset_add_value(Slapi_ValueSet *vs, const Slapi_Value *addval);
extern int slapi_valueset_first_value( Slapi_ValueSet *vs, Slapi_Value **v );
extern int slapi_valueset_next_value( Slapi_ValueSet *vs, int index, Slapi_Value **v);
extern int slapi_valueset_count( const Slapi_ValueSet *vs);
extern void slapi_valueset_set_valueset(Slapi_ValueSet *vs1, const Slapi_ValueSet *vs2);

extern Slapi_Mutex *slapi_new_mutex( void );
extern void slapi_destroy_mutex( Slapi_Mutex *mutex );
extern void slapi_lock_mutex( Slapi_Mutex *mutex );
extern int slapi_unlock_mutex( Slapi_Mutex *mutex );
extern Slapi_CondVar *slapi_new_condvar( Slapi_Mutex *mutex );
extern void slapi_destroy_condvar( Slapi_CondVar *cvar );
extern int slapi_wait_condvar( Slapi_CondVar *cvar, struct timeval *timeout );
extern int slapi_notify_condvar( Slapi_CondVar *cvar, int notify_all );

extern LDAP *slapi_ldap_init( char *ldaphost, int ldapport, int secure, int shared );
extern void slapi_ldap_unbind( LDAP *ld );

extern char *slapi_ch_malloc( unsigned long size );
extern void slapi_ch_free( void **ptr );
extern void slapi_ch_free_string( char **s );
extern char *slapi_ch_calloc( unsigned long nelem, unsigned long size );
extern char *slapi_ch_realloc( char *block, unsigned long size );
extern char *slapi_ch_strdup( char *s );
extern void slapi_ch_array_free( char **arrayp );
extern struct berval *slapi_ch_bvdup(const struct berval *v);
extern struct berval **slapi_ch_bvecdup(const struct berval **v);

/*
 * FIXME: these two were missing, but widely used in a couple of .c files
 */
extern size_t slapi_strlen(char *s );
#define slapi_ch_stlen(s)	slapi_strlen(s)
/*
 * end of FIXME
 */
extern char *slapi_dn_normalize( char *dn );
extern char *slapi_dn_normalize_case( char *dn );
extern char * slapi_esc_dn_normalize( char *dn );
extern char * slapi_esc_dn_normalize_case( char *dn );
extern int slapi_dn_isroot( Slapi_PBlock *pb, char *dn );
extern int slapi_dn_issuffix( char *dn, char *suffix );
char *slapi_dn_beparent( Slapi_PBlock *pb, const char *dn );
char *slapi_dn_parent( const char *dn );
int slapi_dn_isparent( const char *parentdn, const char *childdn );
extern char *slapi_dn_ignore_case( char *dn );
extern char *slapi_get_hostname();
extern void slapi_register_supported_saslmechanism( char *mechanism );
extern void slapi_send_ldap_result( Slapi_PBlock *pb, int err, 
	char *matched, char *text, int nentries, struct berval **urls );
extern int slapi_send_ldap_extended_response(Connection *conn, Operation *op, 
			int errornum, char *respName, struct berval *response);
extern int slapi_send_ldap_search_entry( Slapi_PBlock *pb, Slapi_Entry *e, 
			LDAPControl **ectrls, char **attrs, int attrsonly ); 
extern int slapi_send_ldap_search_reference( Slapi_PBlock *pb, Slapi_Entry *e,
	struct berval **references, LDAPControl **ectrls, struct berval **v2refs );

extern void slapi_register_supported_control(char *controloid, 
					unsigned long controlops);
extern int slapi_get_supported_controls(char ***ctrloidsp, unsigned long **ctrlopsp);
extern int slapi_control_present( LDAPControl **controls, char *oid, 
				struct berval **val, int *iscritical);
extern LDAPControl *slapi_dup_control(LDAPControl *control);
extern void slapi_register_supported_saslmechanism(char *mechanism);
extern char **slapi_get_supported_saslmechanisms();
extern char **slapi_get_supported_extended_ops(void);
extern int checkControlHonored(LDAPControl **controls, char *pControlOid, 
				unsigned long operation, int *isHonored );
extern void slapi_broadcast_be(int funcType, Slapi_PBlock *pPB);
extern Slapi_Filter *slapi_str2filter( char *str );
extern Slapi_Filter *slapi_filter_dup( Slapi_Filter *f );
extern void slapi_filter_free( Slapi_Filter *f, int recurse );
extern int slapi_filter_get_choice( Slapi_Filter *f);
extern int slapi_filter_get_ava( Slapi_Filter *f, char **type, struct berval **bval );
extern Slapi_Filter *slapi_filter_list_first( Slapi_Filter *f );
extern Slapi_Filter *slapi_filter_list_next( Slapi_Filter *f, Slapi_Filter *fprev );
extern int slapi_filter_get_attribute_type( Slapi_Filter *f, char **type ); 
extern int slapi_filter_get_subfilt( Slapi_Filter *f, char **type, char **initial,
	char ***any, char **final );
extern Slapi_Filter *slapi_filter_join( int ftype, Slapi_Filter *f1, Slapi_Filter *f2);
extern int slapi_x_filter_append( int choice, Slapi_Filter **pContainingFilter,
	Slapi_Filter **pNextFilter, Slapi_Filter *filterToAppend );
extern int slapi_filter_test( Slapi_PBlock *pb, Slapi_Entry *e, Slapi_Filter *f,
	int verify_access );
extern int slapi_filter_apply( Slapi_Filter *f, FILTER_APPLY_FN fn, void *arg, int *error_code );
extern int slapi_filter_test_simple( Slapi_Entry *e, Slapi_Filter *f);
extern void slapi_free_search_results_internal(Slapi_PBlock *pb);
extern int slapi_is_connection_ssl(Slapi_PBlock *pPB, int *isSSL);
extern int slapi_get_client_port(Slapi_PBlock *pPB, int *fromPort);
extern int slapi_get_num_be(char *type);
extern unsigned long slapi_timer_current_time();
extern unsigned long slapi_timer_get_time(char *label);
extern void slapi_timer_elapsed_time(char *label,unsigned long start);
extern int slapi_audit_init_header( Connection *conn, Operation *op, 
		Audit_record **arp, void **audit_op_str, 	
		int audit_op, int audit_ext_op, int audit_op_str_len); 
extern int slapi_audit_send_record( Slapi_PBlock *pb, Connection *conn, 
						Operation *op, int rc);

extern int slapi_int_pblock_set_operation( Slapi_PBlock *pb, Operation *op );

extern LDAPMod **slapi_int_modifications2ldapmods(Modifications **);
extern Modifications *slapi_int_ldapmods2modifications(LDAPMod **);
extern void slapi_int_free_ldapmods(LDAPMod **);

extern int slapi_compute_add_evaluator(slapi_compute_callback_t function);
extern int slapi_compute_add_search_rewriter(slapi_search_rewrite_callback_t function);
extern int compute_rewrite_search_filter(Slapi_PBlock *pb);
extern int compute_evaluator(computed_attr_context *c, char *type, Slapi_Entry *e, slapi_compute_output_t outputfn);
extern int slapi_int_compute_output_ber(computed_attr_context *c, Slapi_Attr *a, Slapi_Entry *e);
extern int slapi_x_compute_get_pblock(computed_attr_context *c, Slapi_PBlock **pb);

extern int slapi_int_access_allowed(Operation *op, Entry *entry, AttributeDescription *desc, struct berval *val, slap_access_t access, AccessControlState *state);

extern ldap_pvt_thread_mutex_t	slapi_hn_mutex;
extern ldap_pvt_thread_mutex_t	slapi_time_mutex;
extern ldap_pvt_thread_mutex_t	slapi_printmessage_mutex; 
extern char			*slapi_log_file;
extern int			slapi_log_level;


/*
 * Was: slapi_pblock.h
 */

extern Slapi_PBlock *slapi_pblock_new( void );
extern void slapi_pblock_destroy( Slapi_PBlock* );
extern int slapi_pblock_get( Slapi_PBlock *pb, int arg, void *value );
extern int slapi_pblock_set( Slapi_PBlock *pb, int arg, void *value );
extern void slapi_pblock_check_params( Slapi_PBlock *pb, int flag );
extern int slapi_pblock_delete_param( Slapi_PBlock *p, int param );
extern void slapi_pblock_clear( Slapi_PBlock *pb );

/*
 * OpenLDAP extensions
 */
extern int slapi_int_pblock_get_first( Backend *be, Slapi_PBlock **pb );
extern int slapi_int_pblock_get_next( Slapi_PBlock **pb );


/*
 * Was: plugin.h
 */

extern int slapi_int_register_plugin(Backend *be, Slapi_PBlock *pPB);
extern int slapi_int_call_plugins(Backend *be, int funcType, Slapi_PBlock * pPB);
extern int slapi_int_get_plugins(Backend *be, int functype, SLAPI_FUNC **ppFuncPtrs);
extern int slapi_int_register_extop(Backend *pBE, ExtendedOp **opList, Slapi_PBlock *pPB);
extern int slapi_int_get_extop_plugin(struct berval  *reqoid, SLAPI_FUNC *pFuncAddr );
extern int slapi_int_read_config(Backend *be, const char *fname, int lineno,
		int argc, char **argv );
extern int slapi_int_initialize(void);


/*
 * Was: slapi_ops.h
 */

extern Slapi_PBlock *slapi_search_internal( char *base, int scope, char *filter, 
		LDAPControl **controls, char **attrs, int attrsonly );
extern Slapi_PBlock *slapi_modify_internal( char *dn, LDAPMod **mods,
        LDAPControl **controls, int log_change );
extern Slapi_PBlock *slapi_add_entry_internal( Slapi_Entry * e,
		LDAPControl **controls, int log_change );
extern Slapi_PBlock *slapi_add_internal( char * dn, LDAPMod **attrs,
		LDAPControl **controls, int log_changes );
extern Slapi_PBlock *slapi_add_entry_internal( Slapi_Entry * e,
		LDAPControl **controls, int log_change );
extern Slapi_PBlock *slapi_delete_internal( char * dn,  LDAPControl **controls,
		int log_change );
extern Slapi_PBlock *slapi_modrdn_internal( char * olddn, char * newrdn,
		int deloldrdn, LDAPControl **controls, int log_change);
extern char **slapi_get_supported_extended_ops(void);
extern struct berval *slapi_int_get_supported_extop( int );
extern Connection *slapi_int_init_connection(char *DN, int OpType);
extern void slapi_int_connection_destroy( Connection **pConn );

/*
 * Was: slapi_cl.h
 */

extern void slapi_register_changelog_suffix(char *suffix);
extern char **slapi_get_changelog_suffixes();
extern void slapi_update_changelog_counters(long curNum, long numEntries);
extern char *slapi_get_cl_firstNum();
extern char *slapi_get_cl_lastNum();
extern int slapi_add_to_changelog(Slapi_Entry *ent, char *suffix,
		char *chNum, Operation* op);	
extern int slapi_delete_changelog(char *dn, char *suffix, 
		char *chNum, Operation* op);	
extern int slapi_modify_changelog(char *dn, LDAPMod *mods,char *suffix,
		char *chNum, Operation* op); 
extern int slapi_modifyrdn_changelog(char *olddn, char *newRdn, int delRdn, 
		char *suffix, char *chNum, Operation* op);
extern Backend * slapi_cl_get_be(char *dn);

int slapi_int_init_object_extensions(void);
int slapi_int_free_object_extensions(int objecttype, void *object);
int slapi_int_create_object_extensions(int objecttype, void *object);
int slapi_int_clear_object_extensions(int objecttype, void *object);

LDAP_END_DECL

#endif /* _PROTO_SLAPI_H */


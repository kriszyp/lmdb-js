/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#ifndef _SLAPI_UTILS_H
#define _SLAPI_UTILS_H

LDAP_BEGIN_DECL

struct _Audit_record;
typedef struct _Audit_record Audit_record;

#define SLAPI_CONTROL_MANAGEDSAIT_OID "2.16.840.1.113730.3.4.2"
#define SLAPI_CONTROL_SORTEDSEARCH_OID "1.2.840.113556.1.4.473"
#define SLAPI_CONTROL_PAGED_RESULTS_OID "1.2.840.113556.1.4.319"

typedef int (*SLAPI_FUNC)(Slapi_PBlock *pb);

#define MAX_HOSTNAME 512

#define DOMAIN "Domain"
#define TCPIPPATH "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"

typedef struct _slapi_control {
        int			s_ctrl_num;
        char			**s_ctrl_oids;
        unsigned long		*s_ctrl_ops;
} Slapi_Control;

typedef struct _ExtendedOp {
	struct berval		ext_oid;
        SLAPI_FUNC		ext_func;
        Backend			*ext_be;
        struct _ExtendedOp	*ext_next;
} ExtendedOp;

int slapi_log_error( int severity, char *subsystem, char *fmt, ... );
Slapi_Entry *slapi_str2entry( char *s, int flags );
char *slapi_entry2str( Slapi_Entry *e, int *len );
int slapi_entry_attr_merge( Slapi_Entry *e, char *type, struct berval **vals );
int slapi_entry_attr_find( Slapi_Entry *e, char *type, Slapi_Attr **attr );
char *slapi_entry_attr_get_charptr( const Slapi_Entry *e, const char *type );
int slapi_entry_attr_delete( Slapi_Entry *e, char *type );
int slapi_entry_attr_get_int( const Slapi_Entry *e, const char *type );
int slapi_entry_attr_get_long( const Slapi_Entry *e, const char *type );
int slapi_entry_attr_get_uint( const Slapi_Entry *e, const char *type );
int slapi_entry_attr_get_ulong( const Slapi_Entry *e, const char *type );
int slapi_entry_attr_hasvalue( Slapi_Entry *e, const char *type, const char *value );
int slapi_entry_attr_merge_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals );
char *slapi_entry_get_dn( Slapi_Entry *e );
int slapi_x_entry_get_id( Slapi_Entry *e );
void slapi_entry_set_dn( Slapi_Entry *e, char *dn );
Slapi_Entry *slapi_entry_dup( Slapi_Entry *e );
Slapi_Entry *slapi_entry_alloc();
void slapi_entry_free( Slapi_Entry *e );
int slapi_attr_get_values( Slapi_Attr *attr, struct berval ***vals );

/* OpenLDAP AttrSet extensions for virtual attribute service */
Slapi_AttrSet *slapi_x_attrset_new( void );
Slapi_AttrSet *slapi_x_attrset_init( Slapi_AttrSet *as, Slapi_Attr *a );
void slapi_x_attrset_free( Slapi_AttrSet **as );
Slapi_AttrSet *slapi_x_attrset_dup( Slapi_AttrSet *as );
int slapi_x_attrset_add_attr( Slapi_AttrSet *as, Slapi_Attr *a );
int slapi_x_attrset_add_attr_copy( Slapi_AttrSet *as, Slapi_Attr *a );
int slapi_x_attrset_find( Slapi_AttrSet *as, const char *type, Slapi_Attr **attr );
int slapi_x_attrset_merge( Slapi_AttrSet *as, const char *type, Slapi_ValueSet *vals );
int slapi_x_attrset_merge_bervals( Slapi_AttrSet *as, const char *type, struct berval **vals );
int slapi_x_attrset_delete( Slapi_AttrSet *as, const char *type );

/* DS 5.x SLAPI */
int slapi_access_allowed( Slapi_PBlock *pb, Slapi_Entry *e, char *attr, struct berval *val, int access );
int slapi_acl_check_mods( Slapi_PBlock *pb, Slapi_Entry *e, LDAPMod **mods, char **errbuf );
Slapi_Attr *slapi_attr_new( void );
Slapi_Attr *slapi_attr_init( Slapi_Attr *a, const char *type );
void slapi_attr_free( Slapi_Attr **a );
Slapi_Attr *slapi_attr_dup( const Slapi_Attr *attr );
int slapi_attr_add_value( Slapi_Attr *a, const Slapi_Value *v );
int slapi_attr_type2plugin( const char *type, void **pi );
int slapi_attr_get_type( const Slapi_Attr *attr, char **type );
int slapi_attr_get_oid_copy( const Slapi_Attr *attr, char **oidp );
int slapi_attr_get_flags( const Slapi_Attr *attr, unsigned long *flags );
int slapi_attr_flag_is_set( const Slapi_Attr *attr, unsigned long flag );
int slapi_attr_value_cmp( const Slapi_Attr *attr, const struct berval *v1, const struct berval *v2 );
int slapi_attr_value_find( const Slapi_Attr *a, struct berval *v );
#define SLAPI_TYPE_CMP_EXACT	0
#define SLAPI_TYPE_CMP_BASE	1
#define SLAPI_TYPE_CMP_SUBTYPE	2
int slapi_attr_type_cmp( const char *t1, const char *t2, int opt );
int slapi_attr_types_equivalent( const char *t1, const char *t2 );
int slapi_attr_first_value( Slapi_Attr *a, Slapi_Value **v );
int slapi_attr_next_value( Slapi_Attr *a, int hint, Slapi_Value **v );
int slapi_attr_get_numvalues( const Slapi_Attr *a, int *numValues );
int slapi_attr_get_valueset( const Slapi_Attr *a, Slapi_ValueSet **vs );
int slapi_attr_get_bervals_copy( Slapi_Attr *a, struct berval ***vals );
char *slapi_attr_syntax_normalize( const char *s );

Slapi_Value *slapi_value_new( void );
Slapi_Value *slapi_value_new_berval(const struct berval *bval);
Slapi_Value *slapi_value_new_value(const Slapi_Value *v);
Slapi_Value *slapi_value_new_string(const char *s);
Slapi_Value *slapi_value_init(Slapi_Value *v);
Slapi_Value *slapi_value_init_berval(Slapi_Value *v, struct berval *bval);
Slapi_Value *slapi_value_init_string(Slapi_Value *v,const char *s);
Slapi_Value *slapi_value_dup(const Slapi_Value *v);
void slapi_value_free(Slapi_Value **value);
const struct berval *slapi_value_get_berval( const Slapi_Value *value );
Slapi_Value *slapi_value_set_berval( Slapi_Value *value, const struct berval *bval );
Slapi_Value *slapi_value_set_value( Slapi_Value *value, const Slapi_Value *vfrom);
Slapi_Value *slapi_value_set( Slapi_Value *value, void *val, unsigned long len);
int slapi_value_set_string(Slapi_Value *value, const char *strVal);
int slapi_value_set_int(Slapi_Value *value, int intVal);
const char*slapi_value_get_string(const Slapi_Value *value);
int slapi_value_get_int(const Slapi_Value *value); 
unsigned int slapi_value_get_uint(const Slapi_Value *value); 
long slapi_value_get_long(const Slapi_Value *value); 
unsigned long slapi_value_get_ulong(const Slapi_Value *value); 
size_t slapi_value_get_length(const Slapi_Value *value);
int slapi_value_compare(const Slapi_Attr *a,const Slapi_Value *v1,const Slapi_Value *v2);

Slapi_ValueSet *slapi_valueset_new( void );
void slapi_valueset_free(Slapi_ValueSet *vs);
void slapi_valueset_init(Slapi_ValueSet *vs);
void slapi_valueset_done(Slapi_ValueSet *vs);
void slapi_valueset_add_value(Slapi_ValueSet *vs, const Slapi_Value *addval);
int slapi_valueset_first_value( Slapi_ValueSet *vs, Slapi_Value **v );
int slapi_valueset_next_value( Slapi_ValueSet *vs, int index, Slapi_Value **v);
int slapi_valueset_count( const Slapi_ValueSet *vs);
void slapi_valueset_set_valueset(Slapi_ValueSet *vs1, const Slapi_ValueSet *vs2);

char *slapi_ch_malloc( unsigned long size );
void slapi_ch_free( void **ptr );
void slapi_ch_free_string( char **s );
char *slapi_ch_calloc( unsigned long nelem, unsigned long size );
char *slapi_ch_realloc( char *block, unsigned long size );
char *slapi_ch_strdup( char *s );
void slapi_ch_array_free( char **arrayp );
struct berval *slapi_ch_bvdup(const struct berval *v);
struct berval **slapi_ch_bvecdup(const struct berval **v);

/*
 * FIXME: these two were missing, but widely used in a couple of .c files
 */
size_t slapi_strlen(char *s );
#define slapi_ch_stlen(s)	slapi_strlen(s)
/* end of FIXME */
char *slapi_dn_normalize( char *dn );
char *slapi_dn_normalize_case( char *dn );
char * slapi_esc_dn_normalize( char *dn );
char * slapi_esc_dn_normalize_case( char *dn );
int slapi_dn_isroot( Slapi_PBlock *pb, char *dn );
int slapi_dn_issuffix( char *dn, char *suffix );
char *slapi_dn_ignore_case( char *dn );
char *slapi_get_hostname();
void slapi_register_supported_saslmechanism( char *mechanism );
void slapi_send_ldap_result( Slapi_PBlock *pb, int err, 
	char *matched, char *text, int nentries, struct berval **urls );
int slapi_send_ldap_extended_response(Connection *conn, Operation *op, 
			int errornum, char *respName, struct berval *response);
int slapi_send_ldap_search_entry( Slapi_PBlock *pb, Slapi_Entry *e, 
			LDAPControl **ectrls, char **attrs, int attrsonly ); 
void slapi_register_supported_control(char *controloid, 
					unsigned long controlops);
int slapi_get_supported_controls(char ***ctrloidsp, unsigned long **ctrlopsp);
int slapi_control_present( LDAPControl **controls, char *oid, 
				struct berval **val, int *iscritical);
void slapi_register_supported_saslmechanism(char *mechanism);
char **slapi_get_supported_saslmechanisms();
char **slapi_get_supported_extended_ops(void);
int checkControlHonored(LDAPControl **controls, char *pControlOid, 
				unsigned long operation, int *isHonored );
void slapi_broadcast_be(int funcType, Slapi_PBlock *pPB);
Slapi_Filter *slapi_str2filter( char *str );
void slapi_filter_free( Slapi_Filter *f, int recurse );
int slapi_filter_get_choice( Slapi_Filter *f);
int slapi_filter_get_ava( Slapi_Filter *f, char **type, struct berval **bval );
Slapi_Filter *slapi_filter_list_first( Slapi_Filter *f );
Slapi_Filter *slapi_filter_list_next( Slapi_Filter *f, Slapi_Filter *fprev );
void slapi_free_search_results_internal(Slapi_PBlock *pb);
int slapi_is_connection_ssl(Slapi_PBlock *pPB, int *isSSL);
int slapi_get_client_port(Slapi_PBlock *pPB, int *fromPort);
int slapi_get_num_be(char *type);
unsigned long slapi_timer_current_time();
unsigned long slapi_timer_get_time(char *label);
void slapi_timer_elapsed_time(char *label,unsigned long start);
int slapi_audit_init_header( Connection *conn, Operation *op, 
		Audit_record **arp, void **audit_op_str, 	
		int audit_op, int audit_ext_op, int audit_op_str_len); 
int slapi_audit_send_record( Slapi_PBlock *pb, Connection *conn, 
						Operation *op, int rc);

int slapi_x_backend_set_pb( Slapi_PBlock *pb, Backend *be );
int slapi_x_connection_set_pb( Slapi_PBlock *pb, Connection *conn );
int slapi_x_operation_set_pb( Slapi_PBlock *pb, Operation *op );

LDAPMod **slapi_x_modifications2ldapmods(Modifications **);
Modifications *slapi_x_ldapmods2modifications(LDAPMod **);
void slapi_x_free_ldapmods(LDAPMod **);

extern ldap_pvt_thread_mutex_t	slapi_hn_mutex;
extern ldap_pvt_thread_mutex_t	slapi_time_mutex;
extern ldap_pvt_thread_mutex_t	slapi_printmessage_mutex; 
extern char			*slapi_log_file;
extern int			slapi_log_level;

LDAP_END_DECL

#endif /* _SLAPI_UTILS_H */


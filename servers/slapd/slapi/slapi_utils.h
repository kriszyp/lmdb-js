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
int slapi_entry_attr_delete( Slapi_Entry *e, char *type );
char *slapi_entry_get_dn( Slapi_Entry *e );
void slapi_entry_set_dn( Slapi_Entry *e, char *dn );
Slapi_Entry *slapi_entry_dup( Slapi_Entry *e );
Slapi_Entry *slapi_entry_alloc();
void slapi_entry_free( Slapi_Entry *e );
int slapi_attr_get_values( Slapi_Attr *attr, struct berval ***vals );
char *slapi_ch_malloc( unsigned long size );
void slapi_ch_free( void *ptr );
char *slapi_ch_calloc( unsigned long nelem, unsigned long size );
char *slapi_ch_realloc( char *block, unsigned long size );
char *slapi_ch_strdup( char *s );
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

void slapi_backend_set_pb( Slapi_PBlock *pb, Backend *be );
void slapi_connection_set_pb( Slapi_PBlock *pb, Connection *conn );
void slapi_operation_set_pb( Slapi_PBlock *pb, Operation *op );

extern ldap_pvt_thread_mutex_t	slapi_hn_mutex;
extern ldap_pvt_thread_mutex_t	slapi_time_mutex;
extern ldap_pvt_thread_mutex_t	slapi_printmessage_mutex; 
extern char			*slapi_log_file;
extern int			slapi_log_level;

#endif /* _SLAPI_UTILS_H */


/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2005 The OpenLDAP Foundation.
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
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#ifndef PROTO_LDAP_H
#define PROTO_LDAP_H

LDAP_BEGIN_DECL

extern BI_init			ldap_back_initialize;

extern BI_open			ldap_back_open;
extern BI_close			ldap_back_close;
extern BI_destroy		ldap_back_destroy;

extern BI_db_init		ldap_back_db_init;
extern BI_db_open		ldap_back_db_open;
extern BI_db_destroy		ldap_back_db_destroy;
extern BI_db_config		ldap_back_db_config;

extern BI_op_bind		ldap_back_bind;
extern BI_op_search		ldap_back_search;
extern BI_op_compare		ldap_back_compare;
extern BI_op_modify		ldap_back_modify;
extern BI_op_modrdn		ldap_back_modrdn;
extern BI_op_add		ldap_back_add;
extern BI_op_delete		ldap_back_delete;
extern BI_op_abandon		ldap_back_abandon;
extern BI_op_extended		ldap_back_extended;

extern BI_connection_destroy	ldap_back_conn_destroy;

extern BI_entry_get_rw		ldap_back_entry_get;

int ldap_back_freeconn( Operation *op, struct ldapconn *lc );
struct ldapconn *ldap_back_getconn(struct slap_op *op, struct slap_rep *rs, ldap_back_send_t sendok);
int ldap_back_dobind(struct ldapconn *lc, Operation *op, SlapReply *rs, ldap_back_send_t sendok);
int ldap_back_retry(struct ldapconn *lc, Operation *op, SlapReply *rs, ldap_back_send_t sendok);
int ldap_back_map_result(SlapReply *rs);
int ldap_back_op_result(struct ldapconn *lc, Operation *op, SlapReply *rs,
	ber_int_t msgid, ldap_back_send_t sendok);
int	back_ldap_LTX_init_module(int argc, char *argv[]);

extern int ldap_back_conn_cmp( const void *c1, const void *c2);
extern int ldap_back_conn_dup( void *c1, void *c2 );
extern void ldap_back_conn_free( void *c );

extern int
ldap_back_proxy_authz_ctrl(
		struct ldapconn	*lc,
		Operation	*op,
		SlapReply	*rs,
		LDAPControl	***pctrls );

extern int
ldap_back_proxy_authz_ctrl_free(
		Operation	*op,
		LDAPControl	***pctrls );

extern int chain_init( void );

LDAP_END_DECL

#endif /* PROTO_LDAP_H */

/* back-ldap.h - ldap backend header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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

#ifndef SLAPD_LDAP_H
#define SLAPD_LDAP_H

#include "proto-ldap.h"

#ifdef LDAP_DEVEL
#define LDAP_BACK_PROXY_AUTHZ
#endif

LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;
struct slap_backend_db;

struct ldapconn {
	struct slap_conn	*lc_conn;
	LDAP			*lc_ld;
	struct berval		lc_cred;
	struct berval 		lc_bound_ndn;
	struct berval		lc_local_ndn;
	int			lc_bound;
	ldap_pvt_thread_mutex_t	lc_mutex;
};

struct ldapauth {
	struct berval	la_authcID;
	struct berval	la_authcDN;
	struct berval	la_passwd;

	struct berval	la_authzID;
	
	int		la_authmethod;
	int		la_sasl_flags;
	struct berval	la_sasl_mech;
	struct berval	la_sasl_realm;
	
#define LDAP_BACK_AUTH_NONE		0x00U
#define	LDAP_BACK_AUTH_NATIVE_AUTHZ	0x01U
#define	LDAP_BACK_AUTH_OVERRIDE		0x02U
	unsigned 	la_flags;
};

struct ldapinfo {
	char		*url;
	LDAPURLDesc	*lud;
	struct ldapauth acl_la;
#define	acl_authcDN	acl_la.la_authcDN
#define	acl_passwd	acl_la.la_passwd

#ifdef LDAP_BACK_PROXY_AUTHZ
	/* ID assert stuff */
	int		idassert_mode;
#define	LDAP_BACK_IDASSERT_LEGACY	0
#define	LDAP_BACK_IDASSERT_NOASSERT	1
#define	LDAP_BACK_IDASSERT_ANONYMOUS	2
#define	LDAP_BACK_IDASSERT_SELF		3
#define	LDAP_BACK_IDASSERT_OTHERDN	4
#define	LDAP_BACK_IDASSERT_OTHERID	5

	struct ldapauth	idassert_la;
#define	idassert_authcID	idassert_la.la_authcID
#define	idassert_authcDN	idassert_la.la_authcDN
#define	idassert_passwd		idassert_la.la_passwd
#define	idassert_authzID	idassert_la.la_authzID
#define	idassert_authmethod	idassert_la.la_authmethod
#define	idassert_sasl_flags	idassert_la.la_sasl_flags
#define	idassert_sasl_mech	idassert_la.la_sasl_mech
#define	idassert_sasl_realm	idassert_la.la_sasl_realm
#define	idassert_flags		idassert_la.la_flags
	BerVarray	idassert_authz;
	
	int		idassert_ppolicy;
	/* end of ID assert stuff */
#endif /* LDAP_BACK_PROXY_AUTHZ */

	ldap_pvt_thread_mutex_t		conn_mutex;
	int		savecred;
	Avlnode		*conntree;

	int		rwm_started;
};

int ldap_back_freeconn( Operation *op, struct ldapconn *lc );
struct ldapconn *ldap_back_getconn(struct slap_op *op, struct slap_rep *rs);
int ldap_back_dobind(struct ldapconn *lc, Operation *op, SlapReply *rs);
int ldap_back_retry(struct ldapconn *lc, Operation *op, SlapReply *rs);
int ldap_back_map_result(SlapReply *rs);
int ldap_back_op_result(struct ldapconn *lc, Operation *op, SlapReply *rs,
	ber_int_t msgid, int sendok);
int	back_ldap_LTX_init_module(int argc, char *argv[]);

extern int ldap_back_conn_cmp( const void *c1, const void *c2);
extern int ldap_back_conn_dup( void *c1, void *c2 );
extern void ldap_back_conn_free( void *c );

#ifdef LDAP_BACK_PROXY_AUTHZ
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
#endif /* LDAP_BACK_PROXY_AUTHZ */

LDAP_END_DECL

#endif /* SLAPD_LDAP_H */

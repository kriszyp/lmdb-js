/* back-ldap.h - ldap backend header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
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

	ldap_pvt_thread_mutex_t		conn_mutex;
	int		savecred;
	Avlnode		*conntree;

	int		rwm_started;
};

LDAP_END_DECL

#include "proto-ldap.h"

#endif /* SLAPD_LDAP_H */

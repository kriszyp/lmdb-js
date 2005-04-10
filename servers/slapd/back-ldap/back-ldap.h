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
	int			lc_ispriv;
	ldap_pvt_thread_mutex_t	lc_mutex;
};

/*
 * identity assertion modes
 */
enum {
	LDAP_BACK_IDASSERT_LEGACY,
	LDAP_BACK_IDASSERT_NOASSERT,
	LDAP_BACK_IDASSERT_ANONYMOUS,
	LDAP_BACK_IDASSERT_SELF,
	LDAP_BACK_IDASSERT_OTHERDN,
	LDAP_BACK_IDASSERT_OTHERID
};

struct ldapinfo {
	char		*url;
	LDAPURLDesc	*lud;

	slap_bindconf	acl_la;
#define	acl_authcID	acl_la.sb_authcId
#define	acl_authcDN	acl_la.sb_binddn
#define	acl_passwd	acl_la.sb_cred
#define	acl_authzID	acl_la.sb_authzId
#define	acl_authmethod	acl_la.sb_method
#define	acl_sasl_mech	acl_la.sb_saslmech
#define	acl_sasl_realm	acl_la.sb_realm

	/* ID assert stuff */
	int		idassert_mode;

	slap_bindconf	idassert_la;
#define	idassert_authcID	idassert_la.sb_authcId
#define	idassert_authcDN	idassert_la.sb_binddn
#define	idassert_passwd		idassert_la.sb_cred
#define	idassert_authzID	idassert_la.sb_authzId
#define	idassert_authmethod	idassert_la.sb_method
#define	idassert_sasl_mech	idassert_la.sb_saslmech
#define	idassert_sasl_realm	idassert_la.sb_realm

	unsigned 	idassert_flags;
#define LDAP_BACK_AUTH_NONE		0x00U
#define	LDAP_BACK_AUTH_NATIVE_AUTHZ	0x01U
#define	LDAP_BACK_AUTH_OVERRIDE		0x02U

	BerVarray	idassert_authz;
	/* end of ID assert stuff */

	ldap_pvt_thread_mutex_t		conn_mutex;
	unsigned	flags;
#define LDAP_BACK_F_NONE		0x00U
#define LDAP_BACK_F_SAVECRED		0x01U
#define LDAP_BACK_F_USE_TLS		0x02U
#define LDAP_BACK_F_PROPAGATE_TLS	0x04U
#define LDAP_BACK_F_TLS_CRITICAL	0x08U
#define LDAP_BACK_F_CHASE_REFERRALS	0x10U

#define LDAP_BACK_SAVECRED(li)		( (li)->flags & LDAP_BACK_F_SAVECRED )
#define LDAP_BACK_USE_TLS(li)		( (li)->flags & LDAP_BACK_F_USE_TLS )
#define LDAP_BACK_PROPAGATE_TLS(li)	( (li)->flags & LDAP_BACK_F_PROPAGATE_TLS )
#define LDAP_BACK_TLS_CRITICAL(li)	( (li)->flags & LDAP_BACK_F_TLS_CRITICAL )
#define LDAP_BACK_CHASE_REFERRALS(li)	( (li)->flags & LDAP_BACK_F_CHASE_REFERRALS )

	Avlnode		*conntree;

	int		rwm_started;
};

typedef enum ldap_back_send_t {
	LDAP_BACK_DONTSEND		= 0x00,
	LDAP_BACK_SENDOK		= 0x01,
	LDAP_BACK_SENDERR		= 0x02,
	LDAP_BACK_SENDRESULT		= (LDAP_BACK_SENDOK|LDAP_BACK_SENDERR)
} ldap_back_send_t;

LDAP_END_DECL

#include "proto-ldap.h"

#endif /* SLAPD_LDAP_H */

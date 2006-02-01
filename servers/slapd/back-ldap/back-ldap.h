/* back-ldap.h - ldap backend header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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

typedef struct ldapconn_t {
	Connection		*lc_conn;
#define	LDAP_BACK_PCONN		((void *)0x0)
#define	LDAP_BACK_PCONN_TLS	((void *)0x1)
#define	LDAP_BACK_PCONN_ID(c)	((void *)(c) > LDAP_BACK_PCONN_TLS ? (c)->c_connid : -1)
#ifdef HAVE_TLS
#define	LDAP_BACK_PCONN_SET(op)	((op)->o_conn->c_is_tls ? LDAP_BACK_PCONN_TLS : LDAP_BACK_PCONN)
#else /* ! HAVE_TLS */
#define	LDAP_BACK_PCONN_SET(op)	(LDAP_BACK_PCONN)
#endif /* ! HAVE_TLS */

	LDAP			*lc_ld;
	struct berval		lc_cred;
	struct berval 		lc_bound_ndn;
	struct berval		lc_local_ndn;
	unsigned		lc_lcflags;
#define LDAP_BACK_CONN_ISSET(lc,f)	((lc)->lc_lcflags & (f))
#define	LDAP_BACK_CONN_SET(lc,f)	((lc)->lc_lcflags |= (f))
#define	LDAP_BACK_CONN_CLEAR(lc,f)	((lc)->lc_lcflags &= ~(f))
#define	LDAP_BACK_CONN_CPY(lc,f,mlc) \
	do { \
		if ( ((f) & (mlc)->lc_lcflags) == (f) ) { \
			(lc)->lc_lcflags |= (f); \
		} else { \
			(lc)->lc_lcflags &= ~(f); \
		} \
	} while ( 0 )

#define	LDAP_BACK_FCONN_ISBOUND	(0x01)
#define	LDAP_BACK_FCONN_ISANON	(0x02)
#define	LDAP_BACK_FCONN_ISBMASK	(LDAP_BACK_FCONN_ISBOUND|LDAP_BACK_FCONN_ISANON)
#define	LDAP_BACK_FCONN_ISPRIV	(0x04)
#define	LDAP_BACK_FCONN_ISTLS	(0x08)
#define	LDAP_BACK_FCONN_BINDING	(0x10)

#define	LDAP_BACK_CONN_ISBOUND(lc)		LDAP_BACK_CONN_ISSET((lc), LDAP_BACK_FCONN_ISBOUND)
#define	LDAP_BACK_CONN_ISBOUND_SET(lc)		LDAP_BACK_CONN_SET((lc), LDAP_BACK_FCONN_ISBOUND)
#define	LDAP_BACK_CONN_ISBOUND_CLEAR(lc)	LDAP_BACK_CONN_CLEAR((lc), LDAP_BACK_FCONN_ISBMASK)
#define	LDAP_BACK_CONN_ISBOUND_CPY(lc, mlc)	LDAP_BACK_CONN_CPY((lc), LDAP_BACK_FCONN_ISBOUND, (mlc))
#define	LDAP_BACK_CONN_ISANON(lc)		LDAP_BACK_CONN_ISSET((lc), LDAP_BACK_FCONN_ISANON)
#define	LDAP_BACK_CONN_ISANON_SET(lc)		LDAP_BACK_CONN_SET((lc), LDAP_BACK_FCONN_ISANON)
#define	LDAP_BACK_CONN_ISANON_CLEAR(lc)		LDAP_BACK_CONN_ISBOUND_CLEAR((lc))
#define	LDAP_BACK_CONN_ISANON_CPY(lc, mlc)	LDAP_BACK_CONN_CPY((lc), LDAP_BACK_FCONN_ISANON, (mlc))
#define	LDAP_BACK_CONN_ISPRIV(lc)		LDAP_BACK_CONN_ISSET((lc), LDAP_BACK_FCONN_ISPRIV)
#define	LDAP_BACK_CONN_ISPRIV_SET(lc)		LDAP_BACK_CONN_SET((lc), LDAP_BACK_FCONN_ISPRIV)
#define	LDAP_BACK_CONN_ISPRIV_CLEAR(lc)		LDAP_BACK_CONN_CLEAR((lc), LDAP_BACK_FCONN_ISPRIV)
#define	LDAP_BACK_CONN_ISPRIV_CPY(lc, mlc)	LDAP_BACK_CONN_CPY((lc), LDAP_BACK_FCONN_ISPRIV, (mlc))
#define	LDAP_BACK_CONN_ISTLS(lc)		LDAP_BACK_CONN_ISSET((lc), LDAP_BACK_FCONN_ISTLS)
#define	LDAP_BACK_CONN_ISTLS_SET(lc)		LDAP_BACK_CONN_SET((lc), LDAP_BACK_FCONN_ISTLS)
#define	LDAP_BACK_CONN_ISTLS_CLEAR(lc)		LDAP_BACK_CONN_CLEAR((lc), LDAP_BACK_FCONN_ISTLS)
#define	LDAP_BACK_CONN_ISTLS_CPY(lc, mlc)	LDAP_BACK_CONN_CPY((lc), LDAP_BACK_FCONN_ISTLS, (mlc))
#define	LDAP_BACK_CONN_BINDING(lc)		LDAP_BACK_CONN_ISSET((lc), LDAP_BACK_FCONN_BINDING)
#define	LDAP_BACK_CONN_BINDING_SET(lc)		LDAP_BACK_CONN_SET((lc), LDAP_BACK_FCONN_BINDING)
#define	LDAP_BACK_CONN_BINDING_CLEAR(lc)	LDAP_BACK_CONN_CLEAR((lc), LDAP_BACK_FCONN_BINDING)

	unsigned		lc_refcnt;
	unsigned		lc_flags;
	time_t			lc_create_time;
	time_t			lc_time;
} ldapconn_t;

/*
 * identity assertion modes
 */
enum {
	LDAP_BACK_IDASSERT_LEGACY = 1,
	LDAP_BACK_IDASSERT_NOASSERT,
	LDAP_BACK_IDASSERT_ANONYMOUS,
	LDAP_BACK_IDASSERT_SELF,
	LDAP_BACK_IDASSERT_OTHERDN,
	LDAP_BACK_IDASSERT_OTHERID
};

/*
 * operation enumeration for timeouts
 */
enum {
	LDAP_BACK_OP_ADD = 0,
	LDAP_BACK_OP_DELETE,
	LDAP_BACK_OP_MODIFY,
	LDAP_BACK_OP_MODRDN,
	LDAP_BACK_OP_LAST
};

typedef struct ldap_avl_info_t {
	ldap_pvt_thread_mutex_t		lai_mutex;
	Avlnode				*lai_tree;
} ldap_avl_info_t;

typedef struct ldapinfo_t {
	/* li_uri: the string that goes into ldap_initialize()
	 * TODO: use li_acl.sb_uri instead */
	char		*li_uri;
	/* li_bvuri: an array of each single URI that is equivalent;
	 * to be checked for the presence of a certain item */
	BerVarray	li_bvuri;

	slap_bindconf	li_acl;
#define	li_acl_authcID	li_acl.sb_authcId
#define	li_acl_authcDN	li_acl.sb_binddn
#define	li_acl_passwd	li_acl.sb_cred
#define	li_acl_authzID	li_acl.sb_authzId
#define	li_acl_authmethod	li_acl.sb_method
#define	li_acl_sasl_mech	li_acl.sb_saslmech
#define	li_acl_sasl_realm	li_acl.sb_realm
#define	li_acl_secprops	li_acl.sb_secprops

	/* ID assert stuff */
	int		li_idassert_mode;

	slap_bindconf	li_idassert;
#define	li_idassert_authcID	li_idassert.sb_authcId
#define	li_idassert_authcDN	li_idassert.sb_binddn
#define	li_idassert_passwd	li_idassert.sb_cred
#define	li_idassert_authzID	li_idassert.sb_authzId
#define	li_idassert_authmethod	li_idassert.sb_method
#define	li_idassert_sasl_mech	li_idassert.sb_saslmech
#define	li_idassert_sasl_realm	li_idassert.sb_realm
#define	li_idassert_secprops	li_idassert.sb_secprops

	unsigned 	li_idassert_flags;
#define LDAP_BACK_AUTH_NONE		0x00U
#define	LDAP_BACK_AUTH_NATIVE_AUTHZ	0x01U
#define	LDAP_BACK_AUTH_OVERRIDE		0x02U
#define	LDAP_BACK_AUTH_PRESCRIPTIVE	0x04U

	BerVarray	li_idassert_authz;
	/* end of ID assert stuff */

	int		li_nretries;
#define LDAP_BACK_RETRY_UNDEFINED	(-2)
#define LDAP_BACK_RETRY_FOREVER		(-1)
#define LDAP_BACK_RETRY_NEVER		(0)
#define LDAP_BACK_RETRY_DEFAULT		(3)

	unsigned	li_flags;
#define LDAP_BACK_F_NONE		0x00U
#define LDAP_BACK_F_SAVECRED		0x01U
#define LDAP_BACK_F_USE_TLS		0x02U
#define LDAP_BACK_F_PROPAGATE_TLS	0x04U
#define LDAP_BACK_F_TLS_CRITICAL	0x08U
#define LDAP_BACK_F_TLS_USE_MASK	(LDAP_BACK_F_USE_TLS|LDAP_BACK_F_TLS_CRITICAL)
#define LDAP_BACK_F_TLS_PROPAGATE_MASK	(LDAP_BACK_F_PROPAGATE_TLS|LDAP_BACK_F_TLS_CRITICAL)
#define LDAP_BACK_F_TLS_MASK		(LDAP_BACK_F_TLS_USE_MASK|LDAP_BACK_F_TLS_PROPAGATE_MASK)
#define LDAP_BACK_F_CHASE_REFERRALS	0x10U
#define LDAP_BACK_F_PROXY_WHOAMI	0x20U

#define	LDAP_BACK_F_SUPPORT_T_F			0x80U
#define	LDAP_BACK_F_SUPPORT_T_F_DISCOVER	0x40U
#define	LDAP_BACK_F_SUPPORT_T_F_MASK		(LDAP_BACK_F_SUPPORT_T_F|LDAP_BACK_F_SUPPORT_T_F_DISCOVER)

#define	LDAP_BACK_ISSET(li,f)		( ( (li)->li_flags & (f) ) == (f) )
#define LDAP_BACK_SAVECRED(li)		LDAP_BACK_ISSET( (li), LDAP_BACK_F_SAVECRED )
#define LDAP_BACK_USE_TLS(li)		LDAP_BACK_ISSET( (li), LDAP_BACK_F_USE_TLS )
#define LDAP_BACK_PROPAGATE_TLS(li)	LDAP_BACK_ISSET( (li), LDAP_BACK_F_PROPAGATE_TLS )
#define LDAP_BACK_TLS_CRITICAL(li)	LDAP_BACK_ISSET( (li), LDAP_BACK_F_TLS_CRITICAL )
#define LDAP_BACK_CHASE_REFERRALS(li)	LDAP_BACK_ISSET( (li), LDAP_BACK_F_CHASE_REFERRALS )
#define LDAP_BACK_PROXY_WHOAMI(li)	LDAP_BACK_ISSET( (li), LDAP_BACK_F_PROXY_WHOAMI )

	int		li_version;

	ldap_avl_info_t	li_conninfo;

	time_t		li_network_timeout;
	time_t		li_conn_ttl;
	time_t		li_idle_timeout;
	time_t		li_timeout[ LDAP_BACK_OP_LAST ];
} ldapinfo_t;

typedef enum ldap_back_send_t {
	LDAP_BACK_DONTSEND		= 0x00,
	LDAP_BACK_SENDOK		= 0x01,
	LDAP_BACK_SENDERR		= 0x02,
	LDAP_BACK_SENDRESULT		= (LDAP_BACK_SENDOK|LDAP_BACK_SENDERR),
	LDAP_BACK_BINDING		= 0x04,
	LDAP_BACK_BIND_DONTSEND		= (LDAP_BACK_BINDING),
	LDAP_BACK_BIND_SOK		= (LDAP_BACK_BINDING|LDAP_BACK_SENDOK),
	LDAP_BACK_BIND_SERR		= (LDAP_BACK_BINDING|LDAP_BACK_SENDERR),
	LDAP_BACK_BIND_SRES		= (LDAP_BACK_BINDING|LDAP_BACK_SENDRESULT)
} ldap_back_send_t;

/* define to use asynchronous StartTLS */
#define SLAP_STARTTLS_ASYNCHRONOUS

/* timeout to use when calling ldap_result() */
#define	LDAP_BACK_RESULT_TIMEOUT	(0)
#define	LDAP_BACK_RESULT_UTIMEOUT	(100000)
#define	LDAP_BACK_TV_SET(tv) \
	do { \
		(tv)->tv_sec = LDAP_BACK_RESULT_TIMEOUT; \
		(tv)->tv_usec = LDAP_BACK_RESULT_UTIMEOUT; \
	} while ( 0 )

LDAP_END_DECL

#include "proto-ldap.h"

#endif /* SLAPD_LDAP_H */

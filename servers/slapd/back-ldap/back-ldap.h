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

#include "external.h"

/* String rewrite library */
#ifdef ENABLE_REWRITE
#include "rewrite.h"
#endif /* ENABLE_REWRITE */

#ifdef LDAP_DEVEL
#define LDAP_BACK_PROXY_AUTHZ
#endif

LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;
struct slap_backend_db;

struct ldapconn {
	struct slap_conn	*conn;
	LDAP		*ld;
	struct berval	cred;
	struct berval 	bound_dn;
	struct berval	local_dn;
	int		bound;
	ldap_pvt_thread_mutex_t		lc_mutex;
};

struct ldapmap {
	int drop_missing;

	Avlnode *map;
	Avlnode *remap;
};

struct ldapmapping {
	struct berval src;
	struct berval dst;
};

struct ldaprwmap {
	/*
	 * DN rewriting
	 */
#ifdef ENABLE_REWRITE
	struct rewrite_info *rwm_rw;
#else /* !ENABLE_REWRITE */
	/* some time the suffix massaging without librewrite
	 * will be disabled */
	BerVarray rwm_suffix_massage;
#endif /* !ENABLE_REWRITE */

	/*
	 * Attribute/objectClass mapping
	 */
	struct ldapmap rwm_oc;
	struct ldapmap rwm_at;
};

struct ldapinfo {
	struct slap_backend_db	*be;
	char		*url;
	LDAPURLDesc	*lud;
	struct berval binddn;
	struct berval bindpw;
#ifdef LDAP_BACK_PROXY_AUTHZ
	struct berval proxyauthzdn;
	struct berval proxyauthzpw;

	/* ID assert stuff */
	int		idassert_mode;
#define	LDAP_BACK_IDASSERT_LEGACY	0
#define	LDAP_BACK_IDASSERT_NOASSERT	1
#define	LDAP_BACK_IDASSERT_ANONYMOUS	2
#define	LDAP_BACK_IDASSERT_SELF		3
#define	LDAP_BACK_IDASSERT_OTHERDN	4
#define	LDAP_BACK_IDASSERT_OTHERID	5
	struct berval	idassert_id;
	BerVarray	idassert_authz;
	/* end of ID assert stuff */
#endif /* LDAP_BACK_PROXY_AUTHZ */

	ldap_pvt_thread_mutex_t		conn_mutex;
	int savecred;
	Avlnode *conntree;

#if 0
#ifdef ENABLE_REWRITE
	struct rewrite_info *rwinfo;
#else /* !ENABLE_REWRITE */
	BerVarray suffix_massage;
#endif /* !ENABLE_REWRITE */

	struct ldapmap oc_map;
	struct ldapmap at_map;
#endif

	struct ldaprwmap rwmap;
};

/* Whatever context ldap_back_dn_massage needs... */
typedef struct dncookie {
	struct ldaprwmap *rwmap;

#ifdef ENABLE_REWRITE
	Connection *conn;
	char *ctx;
	SlapReply *rs;
#else
	int normalized;
	int tofrom;
#endif
} dncookie;

struct ldapconn *ldap_back_getconn(struct slap_op *op, struct slap_rep *rs);
int ldap_back_dobind(struct ldapconn *lc, Operation *op, SlapReply *rs);
int ldap_back_map_result(SlapReply *rs);
int ldap_back_op_result(struct ldapconn *lc, Operation *op, SlapReply *rs,
	ber_int_t msgid, int sendok);
int	back_ldap_LTX_init_module(int argc, char *argv[]);

int ldap_back_dn_massage(dncookie *dc, struct berval *dn,
	struct berval *res);

extern int ldap_back_conn_cmp( const void *c1, const void *c2);
extern int ldap_back_conn_dup( void *c1, void *c2 );
extern void ldap_back_conn_free( void *c );

/* attributeType/objectClass mapping */
int mapping_cmp (const void *, const void *);
int mapping_dup (void *, void *);

void ldap_back_map_init ( struct ldapmap *lm, struct ldapmapping ** );
void ldap_back_map ( struct ldapmap *map, struct berval *s, struct berval *m,
	int remap );
#define BACKLDAP_MAP	0
#define BACKLDAP_REMAP	1
char *
ldap_back_map_filter(
		struct ldapmap *at_map,
		struct ldapmap *oc_map,
		struct berval *f,
		int remap
);

int
ldap_back_map_attrs(
		struct ldapmap *at_map,
		AttributeName *a,
		int remap,
		char ***mapped_attrs
);

extern void mapping_free ( void *mapping );

extern int ldap_back_map_config(
		struct ldapmap	*oc_map,
		struct ldapmap	*at_map,
		const char	*fname,
		int		lineno,
		int		argc,
		char		**argv );

extern int
ldap_back_filter_map_rewrite(
		dncookie		*dc,
		Filter			*f,
		struct berval		*fstr,
		int			remap );

/* suffix massaging by means of librewrite */
#ifdef ENABLE_REWRITE
extern int suffix_massage_config( struct rewrite_info *info,
		struct berval *pvnc, struct berval *nvnc,
		struct berval *prnc, struct berval *nrnc);
#endif /* ENABLE_REWRITE */
extern int ldap_dnattr_rewrite( dncookie *dc, BerVarray a_vals );
extern int ldap_dnattr_result_rewrite( dncookie *dc, BerVarray a_vals );

#ifdef LDAP_BACK_PROXY_AUTHZ
extern int
ldap_back_proxy_authz_ctrl(
		struct ldapconn	*lc,
		Operation	*op,
		SlapReply	*rs,
		LDAPControl	***pctrls );
#endif /* LDAP_BACK_PROXY_AUTHZ */

LDAP_END_DECL

#endif /* SLAPD_LDAP_H */

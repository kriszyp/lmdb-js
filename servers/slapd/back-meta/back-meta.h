/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
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
#error "include servers/slapd/back-ldap/back-ldap.h before this file!"
#endif /* SLAPD_LDAP_H */

#ifndef SLAPD_META_H
#define SLAPD_META_H

#include "proto-meta.h"

/* String rewrite library */
#include "rewrite.h"
LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;

/* from back-ldap.h before rwm removal */
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

int ldap_back_freeconn( Operation *op, struct ldapconn *lc );
struct ldapconn *ldap_back_getconn(struct slap_op *op, struct slap_rep *rs);
int ldap_back_dobind(struct ldapconn *lc, Operation *op, SlapReply *rs);
int ldap_back_retry(struct ldapconn *lc, Operation *op, SlapReply *rs);
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

/* (end of) from back-ldap.h before rwm removal */

struct metasingleconn {
	int			candidate;
#define	META_NOT_CANDIDATE	0
#define	META_CANDIDATE		1
#define	META_LAST_CONN		-1
	
	LDAP            	*ld;
	struct berval          	bound_dn;
	struct berval		cred;
	int             	bound;
#define META_UNBOUND		0
#define META_BOUND		1
#define META_ANONYMOUS		2
};

#define META_LAST(lsc)		((lsc)->candidate == META_LAST_CONN)

struct metaconn {
	struct slap_conn	*conn;
	struct rewrite_info	*rwinfo;
	
	/*
	 * means that the connection is bound; 
	 * of course only one target actually is ...
	 */
	int             bound_target;
#define META_BOUND_NONE		-1
#define META_BOUND_ALL		-2
	/* supersedes the connection stuff */
	struct metasingleconn *conns;
};

struct metatarget {
	char			*uri;
	struct berval		psuffix;	/* pretty suffix */
	struct berval		suffix;		/* normalized suffix */
	struct berval		binddn;
	struct berval		bindpw;

	struct berval           pseudorootdn;
	struct berval           pseudorootpw;

#if 0
	struct rewrite_info	*rwinfo;

	struct ldapmap		oc_map;
	struct ldapmap		at_map;
#endif
	struct ldaprwmap	rwmap;
};

struct metadncache {
	ldap_pvt_thread_mutex_t mutex;
	Avlnode			*tree;

#define META_DNCACHE_DISABLED   0
#define META_DNCACHE_FOREVER    -1
	long int		ttl;  /* seconds; 0: no cache, -1: no expiry */
};

struct metainfo {
	int			ntargets;
	int			defaulttarget;
	int			network_timeout;
#define META_DEFAULT_TARGET_NONE	-1
	struct metatarget	**targets;

	struct rewrite_info	*rwinfo;
	Backend			*glue_be; 

	struct metadncache	cache;
	
	ldap_pvt_thread_mutex_t	conn_mutex;
	Avlnode			*conntree;

	int			savecred;
};

#define META_OP_ALLOW_MULTIPLE		0x00
#define META_OP_REQUIRE_SINGLE		0x01
#define META_OP_REQUIRE_ALL		0x02
extern struct metaconn *
meta_back_getconn(
		Operation		*op,
		SlapReply		*rs,
		int			op_type,
		struct berval		*dn,
		int			*candidate
);

extern int
meta_back_dobind(
		struct metaconn		*lc,
		Operation		*op
);

extern int
meta_back_is_valid(
		struct metaconn 	*lc, 
		int 			candidate 
);

extern int
meta_back_op_result(
		struct metaconn		*lc,
		Operation		*op,
		SlapReply		*rs
);

extern int
back_meta_LTX_init_module(
		int			argc,
		char			*argv[]
);

extern int
meta_back_conn_cmp(
		const void		*c1,
		const void		*c2
);

extern int
meta_back_conn_dup(
		void			*c1,
		void			*c2
);

/*
 * Candidate stuff
 */
extern int
meta_back_is_candidate(
		struct berval		*nsuffix,
		struct berval		*ndn
);

extern int
meta_back_count_candidates(
		struct metainfo		*li,
		struct berval		*ndn
);

extern int
meta_back_is_candidate_unique(
		struct metainfo		*li,
		struct berval		*ndn
);

extern int
meta_back_select_unique_candidate(
		struct metainfo		*li,
		struct berval		*ndn
);

extern int
meta_clear_unused_candidates(
		struct metainfo		*li,
		struct metaconn		*lc,
		int			candidate,
		int			reallyclean
);

extern int
meta_clear_one_candidate(
		struct metasingleconn	*lc,
		int			reallyclean
);

/*
 * Dn cache stuff (experimental)
 */
extern int
meta_dncache_cmp(
		const void		*c1,
		const void		*c2
);

extern int
meta_dncache_dup(
		void			*c1,
		void			*c2
);

extern int
meta_dncache_get_target(
		struct metadncache	*cache,
		struct berval		*ndn
);

extern int
meta_dncache_update_entry(
		struct metadncache	*cache,
		struct berval		*ndn,
		int			target
);

extern int
meta_dncache_delete_entry(
		struct metadncache	*cache,
		struct berval		*ndn
);

extern void
meta_dncache_free(
		void *entry
);

LDAP_END_DECL

#endif /* SLAPD_META_H */


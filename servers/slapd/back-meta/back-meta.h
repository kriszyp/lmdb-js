/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This work has been developed to fulfill the requirements
 * of SysNet s.n.c. <http:www.sys-net.it> and it has been donated
 * to the OpenLDAP Foundation in the hope that it may be useful
 * to the Open Source community, but WITHOUT ANY WARRANTY.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from 
 *    flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 *                         
 * 4. This notice may not be removed or altered.
 *
 *
 * This software is based on the backend back-ldap, implemented
 * by Howard Chu <hyc@highlandsun.com>, and modified by Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. The contribution of the original software to the present
 * implementation is acknowledged in this copyright statement.
 *
 * A special acknowledgement goes to Howard for the overall architecture
 * (and for borrowing large pieces of code), and to Mark, who implemented
 * from scratch the attribute/objectclass mapping.
 *
 * The original copyright statement follows.
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the
 *    documentation.
 *
 * 4. This notice may not be removed or altered.
 *                
 */ 

#ifndef SLAPD_LDAP_H
#error "include servers/slapd/back-ldap/back-ldap.h before this file!"
#endif /* SLAPD_LDAP_H */

#ifndef SLAPD_META_H
#define SLAPD_META_H

#include "external.h"

/* String rewrite library */
#include "rewrite.h"

LDAP_BEGIN_DECL

struct slap_conn;
struct slap_op;

struct metasingleconn {
	int			candidate;
#define	META_NOT_CANDIDATE	0
#define	META_CANDIDATE		1
	
	LDAP            	*ld;
	struct berval          	bound_dn;
	int             	bound;
#define META_UNBOUND		0
#define META_BOUND		1
#define META_ANONYMOUS		2
};

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
	struct metasingleconn **conns;
};

struct metatarget {
	char			*uri;
	struct berval		psuffix;	/* pretty suffix */
	struct berval		suffix;		/* normalized suffix */
	struct berval		binddn;
	struct berval		bindpw;

	struct berval           pseudorootdn;
	struct berval           pseudorootpw;

	struct rewrite_info	*rwinfo;

	struct ldapmap		oc_map;
	struct ldapmap		at_map;
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
#define META_DEFAULT_TARGET_NONE	-1
	struct metatarget	**targets;

	struct metadncache	cache;
	
	ldap_pvt_thread_mutex_t	conn_mutex;
	Avlnode			*conntree;
};

extern int
meta_back_do_single_bind(
		struct metainfo         *li,
		struct metaconn         *lc,
		struct berval		*dn,
		struct berval		*ndn,
		struct berval		*cred,
		int			method,
		int                     candidate
);


#define META_OP_ALLOW_MULTIPLE		0x00
#define META_OP_REQUIRE_SINGLE		0x01
#define META_OP_REQUIRE_ALL		0x02
extern struct metaconn *
meta_back_getconn(
		struct			metainfo *li,
	       	struct			slap_conn *conn,
		struct			slap_op *op,
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
		Operation		*op
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


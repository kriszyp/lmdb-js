/* rwm.h - dn rewrite/attribute mapping header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
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
/* This is an altered version */
/*
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
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.      
 */

#ifndef RWM_H
#define RWM_H

/* String rewrite library */
#ifdef ENABLE_REWRITE
#include "rewrite.h"
#endif /* ENABLE_REWRITE */

LDAP_BEGIN_DECL

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

int rwm_dn_massage(dncookie *dc, struct berval *dn, struct berval *res);

/* attributeType/objectClass mapping */
int mapping_cmp (const void *, const void *);
int mapping_dup (void *, void *);

void rwm_map_init ( struct ldapmap *lm, struct ldapmapping ** );
void rwm_map ( struct ldapmap *map, struct berval *s, struct berval *m,
	int remap );
#define BACKLDAP_MAP	0
#define BACKLDAP_REMAP	1
char *
rwm_map_filter(
		struct ldapmap *at_map,
		struct ldapmap *oc_map,
		struct berval *f,
		int remap
);

int
rwm_map_attrs(
		struct ldapmap *at_map,
		AttributeName *a,
		int remap,
		char ***mapped_attrs
);

extern void mapping_free ( void *mapping );

extern int rwm_map_config(
		struct ldapmap	*oc_map,
		struct ldapmap	*at_map,
		const char	*fname,
		int		lineno,
		int		argc,
		char		**argv );

extern int
rwm_filter_map_rewrite(
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

LDAP_END_DECL

#endif /* RWM_H */

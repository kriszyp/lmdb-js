/* map.c - ldap backend mapping routines */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
mapping_cmp ( const void *c1, const void *c2 )
{
	struct ldapmapping *map1 = (struct ldapmapping *)c1;
	struct ldapmapping *map2 = (struct ldapmapping *)c2;
	int rc = map1->src.bv_len - map2->src.bv_len;
	if (rc) return rc;
	return ( strcasecmp(map1->src.bv_val, map2->src.bv_val) );
}

int
mapping_dup ( void *c1, void *c2 )
{
	struct ldapmapping *map1 = (struct ldapmapping *)c1;
	struct ldapmapping *map2 = (struct ldapmapping *)c2;

	return( ( strcasecmp(map1->src.bv_val, map2->src.bv_val) == 0 ) ? -1 : 0 );
}

void
ldap_back_map_init ( struct ldapmap *lm, struct ldapmapping **m )
{
	struct ldapmapping *mapping;

	assert( m );

	*m = NULL;
	
	mapping = (struct ldapmapping *)ch_calloc( 2, 
			sizeof( struct ldapmapping ) );
	if ( mapping == NULL ) {
		return;
	}

	ber_str2bv( "objectclass", sizeof("objectclass")-1, 1, &mapping->src);
	ber_dupbv( &mapping->dst, &mapping->src );
	mapping[1].src = mapping->src;
	mapping[1].dst = mapping->dst;

	avl_insert( &lm->map, (caddr_t)mapping, 
			mapping_cmp, mapping_dup );
	avl_insert( &lm->remap, (caddr_t)&mapping[1], 
			mapping_cmp, mapping_dup );
	*m = mapping;
}

void
ldap_back_map ( struct ldapmap *map, struct berval *s, struct berval *bv,
	int remap )
{
	Avlnode *tree;
	struct ldapmapping *mapping, fmapping;

	if (remap == BACKLDAP_REMAP)
		tree = map->remap;
	else
		tree = map->map;

	bv->bv_len = 0;
	bv->bv_val = NULL;
	fmapping.src = *s;
	mapping = (struct ldapmapping *)avl_find( tree, (caddr_t)&fmapping, mapping_cmp );
	if (mapping != NULL) {
		if ( mapping->dst.bv_val )
			*bv = mapping->dst;
		return;
	}

	if (!map->drop_missing)
		*bv = *s;

	return;
}

char *
ldap_back_map_filter(
		struct ldapmap *at_map,
		struct ldapmap *oc_map,
		struct berval *f,
		int remap
)
{
	char *nf, *p, *q, *s, c;
	int len, extra, plen, in_quote;
	struct berval m, tmp;

	if (f == NULL)
		return(NULL);

	len = f->bv_len;
	extra = len;
	len *= 2;
	nf = ch_malloc( len + 1 );
	if (nf == NULL)
		return(NULL);

	/* this loop assumes the filter ends with one
	 * of the delimiter chars -- probably ')'.
	 */

	s = nf;
	q = NULL;
	in_quote = 0;
	for (p = f->bv_val; (c = *p); p++) {
		if (c == '"') {
			in_quote = !in_quote;
			if (q != NULL) {
				plen = p - q;
				AC_MEMCPY(s, q, plen);
				s += plen;
				q = NULL;
			}
			*s++ = c;
		} else if (in_quote) {
			/* ignore everything in quotes --
			 * what about attrs in DNs?
			 */
			*s++ = c;
		} else if (c != '(' && c != ')'
			&& c != '=' && c != '>' && c != '<'
			&& c != '|' && c != '&')
		{
			if (q == NULL)
				q = p;
		} else {
			if (q != NULL) {
				*p = 0;
				tmp.bv_len = p - q;
				tmp.bv_val = q;
				ldap_back_map(at_map, &tmp, &m, remap);
				if (m.bv_val == NULL || m.bv_val[0] == '\0') {
					ldap_back_map(oc_map, &tmp, &m, remap);
					if (m.bv_val == NULL || m.bv_val[0] == '\0') {
						m = tmp;
					}
				}
				extra += p - q;
				plen = m.bv_len;
				extra -= plen;
				if (extra < 0) {
					char *tmpnf;
					while (extra < 0) {
						extra += len;
						len *= 2;
					}
					s -= (long)nf;
					tmpnf = ch_realloc(nf, len + 1);
					if (tmpnf == NULL) {
						ch_free(nf);
						return(NULL);
					}
					nf = tmpnf;
					s += (long)nf;
				}
				AC_MEMCPY(s, m.bv_val, plen);
				s += plen;
				*p = c;
				q = NULL;
			}
			*s++ = c;
		}
	}
	*s = 0;
	return(nf);
}

char **
ldap_back_map_attrs(
		struct ldapmap *at_map,
		AttributeName *an,
		int remap
)
{
	int i, j;
	char **na;
	struct berval mapped;

	if (an == NULL)
		return(NULL);

	for (i = 0; an[i].an_name.bv_val; i++) {
		/*  */
	}

	na = (char **)ch_calloc( i + 1, sizeof(char *) );
	if (na == NULL)
		return(NULL);

	for (i = j = 0; an[i].an_name.bv_val; i++) {
		ldap_back_map(at_map, &an[i].an_name, &mapped, remap);
		if (mapped.bv_val != NULL && mapped.bv_val != '\0')
			na[j++] = mapped.bv_val;
	}
	if (j == 0 && i != 0)
		na[j++] = LDAP_NO_ATTRS;
	na[j] = NULL;

	return(na);
}


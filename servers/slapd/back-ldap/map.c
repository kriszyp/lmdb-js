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
					/*
					 * FIXME: are we sure we need to search 
					 * oc_map if at_map fails?
					 */
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

#ifdef ENABLE_REWRITE

static int
map_attr_value_(
		struct rewrite_info	*info,
		void			*cookie,
		struct ldapmap		*at_map,
		struct ldapmap		*oc_map,
		AttributeDescription 	*ad,
		struct berval		*mapped_attr,
		struct berval		*value,
		struct berval		*mapped_value,
		int			remap )
{
	struct berval		vtmp;
	int			freeval = 0;

	ldap_back_map( at_map, &ad->ad_cname, mapped_attr, remap );
	if ( mapped_attr->bv_val == NULL || mapped_attr->bv_val[0] == '\0') {
		/*
		 * FIXME: are we sure we need to search oc_map if at_map fails?
		 */
		ldap_back_map( oc_map, &ad->ad_cname, mapped_attr, remap );
		if ( mapped_attr->bv_val == NULL || mapped_attr->bv_val[0] == '\0' ) {
			*mapped_attr = ad->ad_cname;
		}
	}

	if ( value == NULL ) {
		return 0;
	}

	if ( strcmp( ad->ad_type->sat_syntax->ssyn_oid, SLAPD_DN_SYNTAX ) == 0 )
	{
	 	switch ( rewrite_session( info, "searchFilter",
 					value->bv_val, cookie, &vtmp.bv_val ) ) {
		case REWRITE_REGEXEC_OK:
			if ( vtmp.bv_val == NULL ) {
				vtmp = *value;
			} else {
				vtmp.bv_len = strlen( vtmp.bv_val );
				freeval = 1;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDAP, DETAIL1, 
				"[rw] searchFilter: \"%s\" -> \"%s\"\n", 
				value->bv_val, vtmp.bv_val, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> searchFilter: \"%s\" -> \"%s\"\n%s",
					value->bv_val, vtmp.bv_val, "" );
#endif /* !NEW_LOGGING */
			break;

		
		case REWRITE_REGEXEC_UNWILLING:
			return -1;

		case REWRITE_REGEXEC_ERR:
			return -1;
		}

	} else if ( ad == slap_schema.si_ad_objectClass || ad == slap_schema.si_ad_structuralObjectClass ) {
		ldap_back_map( oc_map, value, &vtmp, remap );
		if ( vtmp.bv_val == NULL || vtmp.bv_val[0] == '\0' ) {
			vtmp = *value;
		}
		
	} else {
		vtmp = *value;
	}

	filter_escape_value( &vtmp, mapped_value );

	if ( freeval ) {
		ber_memfree( vtmp.bv_val );
	}
	
	return 0;
}

#define map_attr_value(at_map, oc_map, ad, mapped_attr, value, mapped_value, remap) \
	map_attr_value_(info, cookie, (at_map), (oc_map), (ad), (mapped_attr), (value), (mapped_value), (remap))
#define ldap_back_filter_map_rewrite(at_map, oc_map, f, fstr, remap) \
	ldap_back_filter_map_rewrite_(info, cookie, (at_map), (oc_map), (f), (fstr), (remap))

#else /* ! ENABLE_REWRITE */

static int
map_attr_value_(
		struct ldapmap		*at_map,
		struct ldapmap		*oc_map,
		AttributeDescription 	*ad,
		struct berval		*mapped_attr,
		struct berval		*value,
		struct berval		*mapped_value,
		int			remap )
{
	struct berval		vtmp;

	ldap_back_map( at_map, &ad->ad_cname, mapped_attr, remap );
	if ( mapped_attr->bv_val == NULL || mapped_attr->bv_val[0] == '\0') {
		/*
		 * FIXME: are we sure we need to search oc_map if at_map fails?
		 */
		ldap_back_map( oc_map, &ad->ad_cname, mapped_attr, remap );
		if ( mapped_attr->bv_val == NULL || mapped_attr->bv_val[0] == '\0' ) {
			*mapped_attr = ad->ad_cname;
		}
	}

	if ( value == NULL ) {
		return 0;
	}

	if ( strcmp( ad->ad_type->sat_syntax->ssyn_oid, SLAPD_DN_SYNTAX ) == 0 )
	{
		/* FIXME: use suffix massage capabilities */
		vtmp = *value;

	} else if ( ad == slap_schema.si_ad_objectClass || ad == slap_schema.si_ad_structuralObjectClass ) {
		ldap_back_map( oc_map, value, &vtmp, remap );
		if ( vtmp.bv_val == NULL || vtmp.bv_val[0] == '\0' ) {
			vtmp = *value;
		}
		
	} else {
		vtmp = *value;
	}

	filter_escape_value( &vtmp, mapped_value );

	return 0;
}

#define map_attr_value(at_map, oc_map, ad, mapped_attr, value, mapped_value, remap) \
	map_attr_value_((at_map), (oc_map), (ad), (mapped_attr), (value), (mapped_value), (remap))
#define ldap_back_filter_map_rewrite(at_map, oc_map, f, fstr, remap) \
	ldap_back_filter_map_rewrite_((at_map), (oc_map), (f), (fstr), (remap))

#endif /* ! ENABLE_REWRITE */

int
ldap_back_filter_map_rewrite_(
#ifdef ENABLE_REWRITE
		struct rewrite_info	*info,
		void			*cookie,
#endif /* ENABLE_REWRITE */
		struct ldapmap		*at_map,
		struct ldapmap		*oc_map,
		Filter			*f,
		struct berval		*fstr,
		int			remap )
{
	int		i;
	Filter		*p;
	struct berval	atmp;
	struct berval	vtmp;
	ber_len_t	len;

	if ( f == NULL ) {
		ber_str2bv( "No filter!", sizeof("No filter!")-1, 1, fstr );
		return -1;
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		if ( map_attr_value( at_map, oc_map, f->f_av_desc, &atmp,
					&f->f_av_value, &vtmp, remap ) )
		{
			return -1;
		}

		fstr->bv_len = atmp.bv_len + vtmp.bv_len
			+ ( sizeof("(=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=%s)",
			atmp.bv_val, vtmp.bv_val );

		ber_memfree( vtmp.bv_val );
		break;

	case LDAP_FILTER_GE:
		if ( map_attr_value( at_map, oc_map, f->f_av_desc, &atmp,
				&f->f_av_value, &vtmp, remap ) )
		{
			return -1;
		}

		fstr->bv_len = atmp.bv_len + vtmp.bv_len
			+ ( sizeof("(>=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s>=%s)",
			atmp.bv_val, vtmp.bv_val );

		ber_memfree( vtmp.bv_val );
		break;

	case LDAP_FILTER_LE:
		if ( map_attr_value( at_map, oc_map, f->f_av_desc, &atmp,
					&f->f_av_value, &vtmp, remap ) )
		{
			return -1;
		}

		fstr->bv_len = atmp.bv_len + vtmp.bv_len
			+ ( sizeof("(<=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s<=%s)",
			atmp.bv_val, vtmp.bv_val );

		ber_memfree( vtmp.bv_val );
		break;

	case LDAP_FILTER_APPROX:
		if ( map_attr_value( at_map, oc_map, f->f_av_desc, &atmp,
					&f->f_av_value, &vtmp, remap ) )
		{
			return -1;
		}

		fstr->bv_len = atmp.bv_len + vtmp.bv_len
			+ ( sizeof("(~=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s~=%s)",
			atmp.bv_val, vtmp.bv_val );

		ber_memfree( vtmp.bv_val );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		if ( map_attr_value( at_map, oc_map, f->f_sub_desc, &atmp,
					NULL, NULL, remap ) )
		{
			return -1;
		}

		/* cannot be a DN ... */

		fstr->bv_len = atmp.bv_len + ( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			atmp.bv_val );

		if ( f->f_sub_initial.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_initial, &vtmp );

			fstr->bv_len += vtmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len - 2], vtmp.bv_len + 3,
				/* "(attr=" */ "%s*)",
				vtmp.bv_val );

			ber_memfree( vtmp.bv_val );
		}

		if ( f->f_sub_any != NULL ) {
			for ( i = 0; f->f_sub_any[i].bv_val != NULL; i++ ) {
				len = fstr->bv_len;
				filter_escape_value( &f->f_sub_any[i], &vtmp );

				fstr->bv_len += vtmp.bv_len + 1;
				fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

				snprintf( &fstr->bv_val[len - 1], vtmp.bv_len + 3,
					/* "(attr=[init]*[any*]" */ "%s*)",
					vtmp.bv_val );
				ber_memfree( vtmp.bv_val );
			}
		}

		if ( f->f_sub_final.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_final, &vtmp );

			fstr->bv_len += vtmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len - 1], vtmp.bv_len + 3,
				/* "(attr=[init*][any*]" */ "%s)",
				vtmp.bv_val );

			ber_memfree( vtmp.bv_val );
		}

		break;

	case LDAP_FILTER_PRESENT:
		if ( map_attr_value( at_map, oc_map, f->f_desc, &atmp,
					NULL, NULL, remap ) )
		{
			return -1;
		}

		fstr->bv_len = atmp.bv_len + ( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			atmp.bv_val );
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		fstr->bv_len = sizeof("(%)") - 1;
		fstr->bv_val = malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%c)",
			f->f_choice == LDAP_FILTER_AND ? '&' :
			f->f_choice == LDAP_FILTER_OR ? '|' : '!' );

		for ( p = f->f_list; p != NULL; p = p->f_next ) {
			len = fstr->bv_len;

			if ( ldap_back_filter_map_rewrite( at_map, oc_map, p, &vtmp, remap ) )
			{
				return -1;
			}
			
			fstr->bv_len += vtmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-1], vtmp.bv_len + 2, 
				/*"("*/ "%s)", vtmp.bv_val );

			ch_free( vtmp.bv_val );
		}

		break;

	case LDAP_FILTER_EXT: {
		if ( f->f_mr_desc ) {
			if ( map_attr_value( at_map, oc_map, f->f_mr_desc, &atmp,
						&f->f_mr_value, &vtmp, remap ) )
			{
				return -1;
			}

		} else {
			atmp.bv_len = 0;
			atmp.bv_val = "";
			
			filter_escape_value( &f->f_mr_value, &vtmp );
		}
			

		fstr->bv_len = atmp.bv_len +
			( f->f_mr_dnattrs ? sizeof(":dn")-1 : 0 ) +
			( f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_len+1 : 0 ) +
			vtmp.bv_len + ( sizeof("(:=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s%s%s%s:=%s)",
			atmp.bv_val,
			f->f_mr_dnattrs ? ":dn" : "",
			f->f_mr_rule_text.bv_len ? ":" : "",
			f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_val : "",
			vtmp.bv_val );
		ber_memfree( vtmp.bv_val );
		} break;

	case SLAPD_FILTER_COMPUTED:
		ber_str2bv(
			f->f_result == LDAP_COMPARE_FALSE ? "(?=false)" :
			f->f_result == LDAP_COMPARE_TRUE ? "(?=true)" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "(?=undefined)" :
			"(?=error)",
			f->f_result == LDAP_COMPARE_FALSE ? sizeof("(?=false)")-1 :
			f->f_result == LDAP_COMPARE_TRUE ? sizeof("(?=true)")-1 :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? sizeof("(?=undefined)")-1 :
			sizeof("(?=error)")-1,
			1, fstr );
		break;

	default:
		ber_str2bv( "(?=unknown)", sizeof("(?=unknown)")-1, 1, fstr );
		break;
	}

	return 0;
}

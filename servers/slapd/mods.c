/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <ac/string.h>

#include "slap.h"
#include "lutil.h"

int
modify_add_values(
	Entry		*e,
	Modification	*mod,
	int		permissive,
	const char	**text,
	char		*textbuf,
	size_t		textlen )
{
	int		rc;
	const char	*op;
	Attribute	*a;
	Modification	pmod = *mod;

	switch ( mod->sm_op ) {
	case LDAP_MOD_ADD:
		op = "add";
		break;
	case LDAP_MOD_REPLACE:
		op = "replace";
		break;
	default:
		op = "?";
		assert( 0 );
	}

	/* check if values to add exist in attribute */
	a = attr_find( e->e_attrs, mod->sm_desc );
	if ( a != NULL ) {
		int		rc, i, j, p;
		MatchingRule	*mr;

		mr = mod->sm_desc->ad_type->sat_equality;
		if( mr == NULL || !mr->smr_match ) {
			/* do not allow add of additional attribute
				if no equality rule exists */
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/%s: %s: no equality matching rule",
				op, mod->sm_desc->ad_cname.bv_val );
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		if ( permissive ) {
			for ( i = 0; !BER_BVISNULL( &mod->sm_values[i] ); i++ ) {
				/* EMPTY -- just counting 'em */;
			}

			pmod.sm_values = (BerVarray)ch_malloc(
				(i + 1) * sizeof( struct berval ));
			if ( pmod.sm_nvalues != NULL ) {
				pmod.sm_nvalues = (BerVarray)ch_malloc(
					(i + 1) * sizeof( struct berval ));
			}
		}

		/* no normalization is done in this routine nor
		 * in the matching routines called by this routine. 
		 * values are now normalized once on input to the
		 * server (whether from LDAP or from the underlying
		 * database).
		 */
		for ( p = i = 0; !BER_BVISNULL( &mod->sm_values[i] ); i++ ) {
			int	match;

			assert( a->a_vals[0].bv_val != NULL );
			for ( j = 0; !BER_BVISNULL( &a->a_vals[j] ); j++ ) {
				if ( mod->sm_nvalues ) {
					rc = ordered_value_match( &match, mod->sm_desc, mr,
						SLAP_MR_EQUALITY | SLAP_MR_VALUE_OF_ASSERTION_SYNTAX
							| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
							| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
						&a->a_nvals[j], &mod->sm_nvalues[i], text );
				} else {
					rc = ordered_value_match( &match, mod->sm_desc, mr,
						SLAP_MR_EQUALITY | SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
						&a->a_vals[j], &mod->sm_values[i], text );
				}

				if ( rc == LDAP_SUCCESS && match == 0 ) {
					/* value already exists */
					if ( permissive ) break;

					*text = textbuf;
					snprintf( textbuf, textlen,
						"modify/%s: %s: value #%d already exists",
						op, mod->sm_desc->ad_cname.bv_val, i );
					return LDAP_TYPE_OR_VALUE_EXISTS;

				} else if ( rc != LDAP_SUCCESS ) {
					return rc;
				}
			}

			if ( permissive && match != 0 ) {
				if ( pmod.sm_nvalues ) {
					pmod.sm_nvalues[p] = mod->sm_nvalues[i];
				}
				pmod.sm_values[p++] = mod->sm_values[i];
			}
		}

		if ( permissive ) {
			if ( p == 0 ) {
				/* all new values match exist */
				ch_free( pmod.sm_values );
				if ( pmod.sm_nvalues ) ch_free( pmod.sm_nvalues );
				return LDAP_SUCCESS;
			}

			BER_BVZERO( &pmod.sm_values[p] );
			if ( pmod.sm_nvalues ) {
				BER_BVZERO( &pmod.sm_nvalues[p] );
			}
		}
	}

	/* no - add them */
	if ( mod->sm_desc->ad_type->sat_flags & SLAP_AT_ORDERED_VAL ) {
		rc = ordered_value_add( e, mod->sm_desc, a,
			pmod.sm_values, pmod.sm_nvalues );
	} else {
		rc = attr_merge( e, mod->sm_desc, pmod.sm_values, pmod.sm_nvalues );
	}

	if ( a != NULL && permissive ) {
		ch_free( pmod.sm_values );
		if ( pmod.sm_nvalues ) ch_free( pmod.sm_nvalues );
	}

	if ( rc != 0 ) {
		/* this should return result of attr_merge */
		*text = textbuf;
		snprintf( textbuf, textlen,
			"modify/%s: %s: merge error",
			op, mod->sm_desc->ad_cname.bv_val );
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}

int
modify_delete_values(
	Entry	*e,
	Modification	*m,
	int	perm,
	const char	**text,
	char *textbuf, size_t textlen )
{
	return modify_delete_vindex( e, m, perm, text, textbuf, textlen, NULL );
}

int
modify_delete_vindex(
	Entry	*e,
	Modification	*mod,
	int	permissive,
	const char	**text,
	char *textbuf, size_t textlen,
	int *idx )
{
	int		i, j, k, rc = LDAP_SUCCESS;
	Attribute	*a;
	MatchingRule 	*mr = mod->sm_desc->ad_type->sat_equality;
	char		dummy = '\0';
	int		match = 0;

	/*
	 * If permissive is set, then the non-existence of an 
	 * attribute is not treated as an error.
	 */

	/* delete the entire attribute */
	if ( mod->sm_values == NULL ) {
		rc = attr_delete( &e->e_attrs, mod->sm_desc );

		if( permissive ) {
			rc = LDAP_SUCCESS;
		} else if( rc != LDAP_SUCCESS ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such attribute",
				mod->sm_desc->ad_cname.bv_val );
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		}
		return rc;
	}

	if( mr == NULL || !mr->smr_match ) {
		/* disallow specific attributes from being deleted if
			no equality rule */
		*text = textbuf;
		snprintf( textbuf, textlen,
			"modify/delete: %s: no equality matching rule",
			mod->sm_desc->ad_cname.bv_val );
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->sm_desc )) == NULL ) {
		if( permissive ) {
			return LDAP_SUCCESS;
		}
		*text = textbuf;
		snprintf( textbuf, textlen,
			"modify/delete: %s: no such attribute",
			mod->sm_desc->ad_cname.bv_val );
		return LDAP_NO_SUCH_ATTRIBUTE;
	}

	for ( i = 0; !BER_BVISNULL( &mod->sm_values[i] ); i++ ) {
		int	found = 0;
		for ( j = 0; !BER_BVISNULL( &a->a_vals[j] ); j++ ) {
			/* skip already deleted values */
			if ( a->a_vals[j].bv_val == &dummy ) {
				continue;
			}

			if( mod->sm_nvalues ) {
				assert( a->a_nvals != NULL );
				rc = ordered_value_match( &match, a->a_desc, mr,
					SLAP_MR_EQUALITY | SLAP_MR_VALUE_OF_ASSERTION_SYNTAX
						| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
						| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
					&a->a_nvals[j], &mod->sm_nvalues[i], text );
			} else {
#if 0
				assert( a->a_nvals == NULL );
#endif
				rc = ordered_value_match( &match, a->a_desc, mr,
					SLAP_MR_EQUALITY | SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
					&a->a_vals[j], &mod->sm_values[i], text );
			}

			if ( rc != LDAP_SUCCESS ) {
				*text = textbuf;
				snprintf( textbuf, textlen,
					"%s: matching rule failed",
					mod->sm_desc->ad_cname.bv_val );
				break;
			}

			if ( match != 0 ) {
				continue;
			}

			found = 1;

			if ( idx )
				idx[i] = j;

			/* delete value and mark it as dummy */
			free( a->a_vals[j].bv_val );
			a->a_vals[j].bv_val = &dummy;
			if( a->a_nvals != a->a_vals ) {
				free( a->a_nvals[j].bv_val );
				a->a_nvals[j].bv_val = &dummy;
			}

			break;
		}

		if ( found == 0 ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such value",
				mod->sm_desc->ad_cname.bv_val );
			rc = LDAP_NO_SUCH_ATTRIBUTE;
			if ( i > 0 ) {
				break;
			} else {
				goto return_results;
			}
		}
	}

	/* compact array skipping dummies */
	for ( k = 0, j = 0; !BER_BVISNULL( &a->a_vals[k] ); k++ ) {
		/* skip dummies */
		if( a->a_vals[k].bv_val == &dummy ) {
			assert( a->a_nvals[k].bv_val == &dummy );
			continue;
		}
		if ( j != k ) {
			a->a_vals[ j ] = a->a_vals[ k ];
			if (a->a_nvals != a->a_vals) {
				a->a_nvals[ j ] = a->a_nvals[ k ];
			}
		}

		j++;
	}

	BER_BVZERO( &a->a_vals[j] );
	if (a->a_nvals != a->a_vals) {
		BER_BVZERO( &a->a_nvals[j] );
	}

	/* if no values remain, delete the entire attribute */
	if ( BER_BVISNULL( &a->a_vals[0] ) ) {
		if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such attribute",
				mod->sm_desc->ad_cname.bv_val );
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		}
	} else if ( a->a_desc->ad_type->sat_flags & SLAP_AT_ORDERED_VAL ) {
		/* For an ordered attribute, renumber the value indices */
		ordered_value_sort( a, 1 );
	}

return_results:;

	return rc;
}

int
modify_replace_values(
	Entry	*e,
	Modification	*mod,
	int		permissive,
	const char	**text,
	char *textbuf, size_t textlen )
{
	(void) attr_delete( &e->e_attrs, mod->sm_desc );

	if ( mod->sm_values ) {
		return modify_add_values( e, mod, permissive, text, textbuf, textlen );
	}

	return LDAP_SUCCESS;
}

int
modify_increment_values(
	Entry	*e,
	Modification	*mod,
	int	permissive,
	const char	**text,
	char *textbuf, size_t textlen )
{
	Attribute *a;

	a = attr_find( e->e_attrs, mod->sm_desc );
	if( a == NULL ) {
		if ( permissive ) {
			Modification modReplace = *mod;

			modReplace.sm_op = LDAP_MOD_REPLACE;

			return modify_add_values(e, &modReplace, permissive, text, textbuf, textlen);
		} else {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/increment: %s: no such attribute",
				mod->sm_desc->ad_cname.bv_val );
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	if ( !strcmp( a->a_desc->ad_type->sat_syntax_oid, SLAPD_INTEGER_SYNTAX )) {
		int i;
		char str[sizeof(long)*3 + 2]; /* overly long */
		long incr;

		if ( lutil_atol( &incr, mod->sm_values[0].bv_val ) != 0 ) {
			*text = "modify/increment: invalid syntax of increment";
			return LDAP_INVALID_SYNTAX;
		}

		/* treat zero and errors as a no-op */
		if( incr == 0 ) {
			return LDAP_SUCCESS;
		}

		for( i = 0; !BER_BVISNULL( &a->a_nvals[i] ); i++ ) {
			char *tmp;
			long value;
			size_t strln;
			if ( lutil_atol( &value, a->a_nvals[i].bv_val ) != 0 ) {
				*text = "modify/increment: invalid syntax of original value";
				return LDAP_INVALID_SYNTAX;
			}
			strln = snprintf( str, sizeof(str), "%ld", value+incr );

			tmp = SLAP_REALLOC( a->a_nvals[i].bv_val, strln+1 );
			if( tmp == NULL ) {
				*text = "modify/increment: reallocation error";
				return LDAP_OTHER;
			}
			a->a_nvals[i].bv_val = tmp;
			a->a_nvals[i].bv_len = strln;

			AC_MEMCPY( a->a_nvals[i].bv_val, str, strln+1 );
		}

	} else {
		snprintf( textbuf, textlen,
			"modify/increment: %s: increment not supported for value syntax %s",
			mod->sm_desc->ad_cname.bv_val,
			a->a_desc->ad_type->sat_syntax_oid );
		return LDAP_CONSTRAINT_VIOLATION;
	}

	return LDAP_SUCCESS;
}

void
slap_mod_free(
	Modification	*mod,
	int				freeit )
{
	if ( mod->sm_values != NULL ) ber_bvarray_free( mod->sm_values );
	mod->sm_values = NULL;

	if ( mod->sm_nvalues != NULL ) ber_bvarray_free( mod->sm_nvalues );
	mod->sm_nvalues = NULL;

	if( freeit ) free( mod );
}

void
slap_mods_free(
    Modifications	*ml,
    int			freevals )
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		if ( freevals )
			slap_mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}


/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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

int
modify_check_duplicates(
	AttributeDescription	*ad,
	MatchingRule		*mr,
	BerVarray		vals,
	BerVarray		mods,
	int			permissive,
	const char	**text,
	char *textbuf, size_t textlen )
{
	int		i, j, numvals = 0, nummods,
			rc = LDAP_SUCCESS, matched;
	/* this function is no longer used */
	return rc;
}

int
modify_add_values(
	Entry	*e,
	Modification	*mod,
	int	permissive,
	const char	**text,
	char *textbuf, size_t textlen )
{
	int		i, j;
	int		matched;
	Attribute	*a;
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;
	const char *op;

	switch( mod->sm_op ) {
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

	a = attr_find( e->e_attrs, mod->sm_desc );

	/*
	 * With permissive set, as long as the attribute being added
	 * has the same value(s?) as the existing attribute, then the
	 * modify will succeed.
	 */

	/* check if the values we're adding already exist */
	if( mr == NULL || !mr->smr_match ) {
		if ( a != NULL ) {
			/* do not allow add of additional attribute
				if no equality rule exists */
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/%s: %s: no equality matching rule",
				op, mod->sm_desc->ad_cname.bv_val );
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
			/* test asserted values against existing values */
			if( a ) {
				for( matched = 0, j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
					if ( bvmatch( &mod->sm_bvalues[i], &a->a_vals[j] ) ) {
						if ( permissive ) {
							matched++;
							continue;
						}
						/* value exists already */
						*text = textbuf;
						snprintf( textbuf, textlen,
							"modify/%s: %s: value #%i already exists",
							op, mod->sm_desc->ad_cname.bv_val, j );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
				if ( permissive && matched == j ) {
					/* values already exist; do nothing */
					return LDAP_SUCCESS;
				}
			}

			/* test asserted values against themselves */
			for( j = 0; j < i; j++ ) {
				if ( bvmatch( &mod->sm_bvalues[i], &mod->sm_bvalues[j] ) ) {
					/* value exists already */
					*text = textbuf;
					snprintf( textbuf, textlen,
						"modify/%s: %s: value #%i already exists",
						op, mod->sm_desc->ad_cname.bv_val, j );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}
		}

	} else {
		/* no normalization is done in this routine nor
		 * in the matching routines called by this routine. 
		 * values are now normalized once on input to the
		 * server (whether from LDAP or from the underlying
		 * database).
		 * This should outperform the old code.  No numbers
		 * are available yet.
		 */

		int		rc;

		if ( mod->sm_bvalues[1].bv_val == 0 ) {
			if ( a != NULL ) {
				int		i;

				for ( matched = 0, i = 0; a->a_vals[ i ].bv_val; i++ ) {
					int	match;

					if( mod->sm_nvalues ) {
						rc = value_match( &match, mod->sm_desc, mr,
							SLAP_MR_EQUALITY
								| SLAP_MR_VALUE_OF_ASSERTION_SYNTAX
								| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
								| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
							&a->a_nvals[i],
							&mod->sm_nvalues[0],
							text );

					} else {
						rc = value_match( &match, mod->sm_desc, mr,
							SLAP_MR_EQUALITY
								| SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
							&a->a_vals[i],
							&mod->sm_values[0],
							text );
					}


					if( rc == LDAP_SUCCESS && match == 0 ) {
						if ( permissive ) {
							matched++;
							continue;
						}
						*text = textbuf;
						snprintf( textbuf, textlen,
							"modify/%s: %s: value #0 already exists",
							op, mod->sm_desc->ad_cname.bv_val );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
				if ( permissive && matched == i ) {
					/* values already exist; do nothing */
					return LDAP_SUCCESS;
				}
			}

		} else {
			rc = modify_check_duplicates( mod->sm_desc, mr,
				a ? a->a_vals : NULL, mod->sm_bvalues,
				permissive, text, textbuf, textlen );

			if ( permissive && rc == LDAP_TYPE_OR_VALUE_EXISTS ) {
				return LDAP_SUCCESS;
			}

			if ( rc != LDAP_SUCCESS ) {
				return rc;
			}
		}
	}

	/* no - add them */
	if( attr_merge( e, mod->sm_desc, mod->sm_values, mod->sm_nvalues ) != 0 ) {
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
	Modification	*mod,
	int	permissive,
	const char	**text,
	char *textbuf, size_t textlen
)
{
	int		i, j, k, rc = LDAP_SUCCESS;
	Attribute	*a;
	MatchingRule 	*mr = mod->sm_desc->ad_type->sat_equality;
	char		dummy = '\0';
	int			match = 0;

	/*
	 * If permissive is set, then the non-existence of an 
	 * attribute is not treated as an error.
	 */

	/* delete the entire attribute */
	if ( mod->sm_bvalues == NULL ) {
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


	for ( i = 0; mod->sm_values[i].bv_val != NULL; i++ ) {
		int	found = 0;
		for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {

			if( mod->sm_nvalues ) {
				assert( a->a_nvals );
				rc = (*mr->smr_match)( &match,
					SLAP_MR_VALUE_OF_ASSERTION_SYNTAX
						| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
						| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
					a->a_desc->ad_type->sat_syntax,
					mr, &a->a_nvals[j],
					&mod->sm_nvalues[i] );
			} else {
#if 0
				assert( a->a_nvals == NULL );
#endif
				rc = (*mr->smr_match)( &match,
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					a->a_desc->ad_type->sat_syntax,
					mr, &a->a_vals[j],
					&mod->sm_values[i] );
			}

			if ( rc != LDAP_SUCCESS ) {
				*text = textbuf;
				snprintf( textbuf, textlen,
					"%s: matching rule failed",
					mod->sm_desc->ad_cname.bv_val );
				goto return_results;
			}

			if ( match != 0 ) {
				continue;
			}

			found = 1;

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
			goto return_results;
		}
	}

	/* compact array skipping dummies */
	for ( k = 0, j = 0; a->a_vals[k].bv_val != NULL; k++ ) {
		/* skip dummies */
		if( a->a_vals[k].bv_val == &dummy ) {
			assert( a->a_nvals == NULL || a->a_nvals[k].bv_val == &dummy );
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

	a->a_vals[j].bv_val = NULL;
	if (a->a_nvals != a->a_vals) a->a_nvals[j].bv_val = NULL;

	/* if no values remain, delete the entire attribute */
	if ( a->a_vals[0].bv_val == NULL ) {
		if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such attribute",
				mod->sm_desc->ad_cname.bv_val );
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		}
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

	if ( mod->sm_bvalues ) {
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
		*text = textbuf;
		snprintf( textbuf, textlen,
			"modify/increment: %s: no such attribute",
			mod->sm_desc->ad_cname.bv_val );
		return LDAP_NO_SUCH_ATTRIBUTE;
	}


	if ( !strcmp( a->a_desc->ad_type->sat_syntax_oid, SLAPD_INTEGER_SYNTAX )) {
		int i;
		char str[sizeof(long)*3 + 2]; /* overly long */
		long incr = atol( mod->sm_bvalues[0].bv_val );

		/* treat zero and errors as a no-op */
		if( incr == 0 ) {
			return LDAP_SUCCESS;
		}

		for( i=0; a->a_nvals[i].bv_val != NULL; i++ ) {
			char *tmp;
			long value = atol( a->a_nvals[i].bv_val );
			size_t strln = snprintf( str, sizeof(str), "%ld", value+incr );

			tmp = SLAP_REALLOC( a->a_nvals[i].bv_val, strln+1 );
			if( tmp == NULL ) {
				*text = "modify/increment: reallocation error";
				return LDAP_OTHER;;
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
    Modifications	*ml )
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		slap_mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}


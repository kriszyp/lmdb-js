/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

#include "slap.h"

#undef QUICK_DIRTY_DUPLICATE_CHECK

int
modify_check_duplicates(
	AttributeDescription	*ad,
	MatchingRule		*mr,
	BerVarray		vals,
	BerVarray		mods,
	const char	**text,
	char *textbuf, size_t textlen )
{
	int		i, j, rc = LDAP_SUCCESS;
	BerVarray	nvals = NULL, nmods;

	/*
	 * FIXME: better do the following
	 * 
	 *   - count the existing values
	 *   - count the new values
	 *   
	 *   - if the existing values are less than the new ones {
	 *       // current code
	 *       - normalize the existing values
	 *       - for each new value {
	 *           - normalize
	 *           - check with existing
	 *           - cross-check with already normalized new vals
	 *       }
	 *   } else {
	 *       // to be implemented
	 *       - for each new value {
	 *           - normalize
	 *           - cross-check with already normalized new vals
	 *       }
	 *       - for each existing value {
	 *           - normalize
	 *           - check with already normalized new values
	 *       }
	 *   }
	 *
	 * The first case is good when adding a lot of new values,
	 * and significantly at first import of values (e.g. adding
	 * a new group); the latter case seems to be quite important
	 * as well, because it is likely to be the most frequently
	 * used when administering the entry.  The current 
	 * implementation will always normalize all the existing
	 * values before checking.  If there's no duplicate, the
	 * performances should not change; they will in case of error.
	 */

	if ( vals ) {
		for ( j = 0; vals[ j ].bv_val != NULL; j++ )
			/* count existing values */ ;

		nvals = ch_calloc( j + 1, sizeof( struct berval ) );

		/* normalize the existing values first */
		for ( j = 0; vals[ j ].bv_val != NULL; j++ ) {
			rc = value_normalize( ad, SLAP_MR_EQUALITY,
				&vals[ j ], &nvals[ j ], text );

			/* existing attribute values must normalize */
			assert( rc == LDAP_SUCCESS );

			if ( rc != LDAP_SUCCESS ) {
				nvals[ j ].bv_val = NULL;
				goto return_results;
			}
		}
		nvals[ j ].bv_val = NULL;
	}

	for ( i = 0; mods[ i ].bv_val != NULL; i++ )
		/* count new values */ ;

	nmods = ch_calloc( i + 1, sizeof( struct berval ) );

	for ( i = 0; mods[ i ].bv_val != NULL; i++ ) {

		rc = value_normalize( ad, SLAP_MR_EQUALITY,
			&mods[ i ], &nmods[ i ], text );

		if ( rc != LDAP_SUCCESS ) {
			nmods[ i ].bv_val = NULL;
			goto return_results;
		}

		if ( vals ) {
			for ( j = 0; nvals[ j ].bv_val; j++ ) {
#ifdef QUICK_DIRTY_DUPLICATE_CHECK
				if ( bvmatch( &nmods[ i ], &nvals[ j ] ) ) {
#else /* !QUICK_DIRTY_DUPLICATE_CHECK */
				int match;

				rc = (mr->smr_match)( &match,
					SLAP_MR_VALUE_SYNTAX_MATCH,
					ad->ad_type->sat_syntax,
					mr, &nmods[ i ], &nvals[ j ] );
				if ( rc != LDAP_SUCCESS ) {
					nmods[ i + 1 ].bv_val = NULL;
					goto return_results;
				}
	
				if ( match == 0 ) {
#endif /* !QUICK_DIRTY_DUPLICATE_CHECK */
					snprintf( textbuf, textlen,
						"%s: value #%d provided more than once",
						ad->ad_cname.bv_val, i );
					rc = LDAP_TYPE_OR_VALUE_EXISTS;
					nmods[ i + 1 ].bv_val = NULL;
					goto return_results;
				}
			}
		}

		for ( j = 0; j < i; j++ ) {
#ifdef QUICK_DIRTY_DUPLICATE_CHECK
			if ( bvmatch( &nmods[ i ], &nmods[ j ] ) ) {
#else /* !QUICK_DIRTY_DUPLICATE_CHECK */
			int match;

			rc = (mr->smr_match)( &match,
				SLAP_MR_VALUE_SYNTAX_MATCH,
				ad->ad_type->sat_syntax,
				mr, &nmods[ i ], &nmods[ j ] );
			if ( rc != LDAP_SUCCESS ) {
				nmods[ i + 1 ].bv_val = NULL;
				goto return_results;
			}

			if ( match == 0 ) {
#endif /* !QUICK_DIRTY_DUPLICATE_CHECK */
				snprintf( textbuf, textlen,
					"%s: value #%d provided more than once",
					ad->ad_cname.bv_val, j );
				rc = LDAP_TYPE_OR_VALUE_EXISTS;
				nmods[ i + 1 ].bv_val = NULL;
				goto return_results;
			}
		}
	}
	nmods[ i ].bv_val = NULL;

return_results:;
	if ( nvals ) {
		ber_bvarray_free( nvals );
	}
	if ( nmods ) {
		ber_bvarray_free( nmods );
	}

	return rc;
}

int
modify_add_values(
	Entry	*e,
	Modification	*mod,
	const char	**text,
	char *textbuf, size_t textlen
)
{
	int		i, j;
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
				for( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
					if ( bvmatch( &mod->sm_bvalues[i],
						&a->a_vals[j] ) ) {

						/* value exists already */
						*text = textbuf;
						snprintf( textbuf, textlen,
							"modify/%s: %s: value #%i already exists",
							op, mod->sm_desc->ad_cname.bv_val, j );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
			}

			/* test asserted values against themselves */
			for( j = 0; j < i; j++ ) {
				if ( bvmatch( &mod->sm_bvalues[i],
					&mod->sm_bvalues[j] ) ) {

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

		/*
		 * The original code performs ( n ) normalizations 
		 * and ( n * ( n - 1 ) / 2 ) matches, which hide
		 * the same number of normalizations.  The new code
		 * performs the same number of normalizations ( n )
		 * and ( n * ( n - 1 ) / 2 ) mem compares, far less
		 * expensive than an entire match, if a match is
		 * equivalent to a normalization and a mem compare ...
		 * 
		 * This is far more memory expensive than the previous,
		 * but it can heavily improve performances when big
		 * chunks of data are added (typical example is a group
		 * with thousands of DN-syntax members; on my system:
		 * for members of 5-RDN DNs,

		members		orig		bvmatch (dirty)	new
		1000		0m38.456s	0m0.553s 	0m0.608s
		2000		2m33.341s	0m0.851s	0m1.003s

		 * Moreover, 100 groups with 10000 members each were
		 * added in 37m27.933s (an analogous LDIF file was
		 * loaded into Active Directory in 38m28.682s, BTW).
		 * 
		 * Maybe we could switch to the new algorithm when
		 * the number of values overcomes a given threshold?
		 */

		int		rc;
		const char	*text = NULL;
		char		textbuf[ SLAP_TEXT_BUFLEN ] = { '\0' };

		if ( mod->sm_bvalues[ 1 ].bv_val == 0 ) {
			if ( a != NULL ) {
				struct berval	asserted;
				int		i;

				rc = value_normalize( mod->sm_desc, SLAP_MR_EQUALITY,
					&mod->sm_bvalues[ 0 ], &asserted, &text );

				if ( rc != LDAP_SUCCESS ) {
					return rc;
				}

				for ( i = 0; a->a_vals[ i ].bv_val; i++ ) {
					int	match;

					rc = value_match( &match, mod->sm_desc, mr,
						SLAP_MR_VALUE_SYNTAX_MATCH,
						&a->a_vals[ i ], &asserted, &text );

					if( rc == LDAP_SUCCESS && match == 0 ) {
						free( asserted.bv_val );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
			}

		} else {
			rc = modify_check_duplicates( mod->sm_desc, mr,
					a ? a->a_vals : NULL, mod->sm_bvalues,
					&text, textbuf, sizeof( textbuf ) );
	
			if ( rc != LDAP_SUCCESS ) {
				return rc;
			}
		}
	}

	/* no - add them */
	if( attr_merge( e, mod->sm_desc, mod->sm_bvalues ) != 0 ) {
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
	const char	**text,
	char *textbuf, size_t textlen
)
{
	int		i, j, k, found;
	Attribute	*a;
	MatchingRule 	*mr = mod->sm_desc->ad_type->sat_equality;

	/* delete the entire attribute */
	if ( mod->sm_bvalues == NULL ) {
		int rc = attr_delete( &e->e_attrs, mod->sm_desc );

		if( rc != LDAP_SUCCESS ) {
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
		*text = textbuf;
		snprintf( textbuf, textlen,
			"modify/delete: %s: no such attribute",
			mod->sm_desc->ad_cname.bv_val );
		return LDAP_NO_SUCH_ATTRIBUTE;
	}

	/* find each value to delete */
	for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
		int rc;
		struct berval asserted;

		rc = value_normalize( mod->sm_desc,
			SLAP_MR_EQUALITY,
			&mod->sm_bvalues[i],
			&asserted,
			text );

		if( rc != LDAP_SUCCESS ) return rc;

		found = 0;
		for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
			int match;
			int rc = value_match( &match, mod->sm_desc, mr,
				SLAP_MR_VALUE_SYNTAX_MATCH,
				&a->a_vals[j], &asserted, text );

			if( rc == LDAP_SUCCESS && match != 0 ) {
				continue;
			}

			/* found a matching value */
			found = 1;

			/* delete it */
			free( a->a_vals[j].bv_val );
			for ( k = j + 1; a->a_vals[k].bv_val != NULL; k++ ) {
				a->a_vals[k - 1] = a->a_vals[k];
			}
			a->a_vals[k - 1].bv_val = NULL;
			a->a_vals[k - 1].bv_len = 0;

			break;
		}

		free( asserted.bv_val );

		/* looked through them all w/o finding it */
		if ( ! found ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such value",
				mod->sm_desc->ad_cname.bv_val );
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	/* if no values remain, delete the entire attribute */
	if ( a->a_vals[0].bv_val == NULL ) {
		if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
			*text = textbuf;
			snprintf( textbuf, textlen,
				"modify/delete: %s: no such attribute",
				mod->sm_desc->ad_cname.bv_val );
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	return LDAP_SUCCESS;
}

int
modify_replace_values(
	Entry	*e,
	Modification	*mod,
	const char	**text,
	char *textbuf, size_t textlen
)
{
	(void) attr_delete( &e->e_attrs, mod->sm_desc );

	if ( mod->sm_bvalues ) {
		return modify_add_values( e, mod, text, textbuf, textlen );
	}

	return LDAP_SUCCESS;
}

void
slap_mod_free(
	Modification	*mod,
	int				freeit
)
{
#if 0
	if ( mod->sm_type.bv_val)
		free( mod->sm_type.bv_val );
#endif
	if ( mod->sm_bvalues != NULL )
		ber_bvarray_free( mod->sm_bvalues );

	if( freeit )
		free( mod );
}

void
slap_mods_free(
    Modifications	*ml
)
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		slap_mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}


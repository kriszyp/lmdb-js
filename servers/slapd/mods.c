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
					int rc = ber_bvcmp( &mod->sm_bvalues[i],
						&a->a_vals[j] );

					if( rc == 0 ) {
						/* value exists already */
						*text = textbuf;
						snprintf( textbuf, textlen,
							"modify/%s: %s: value #%i already exists",
							op, mod->sm_desc->ad_cname.bv_val );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
			}

			/* test asserted values against themselves */
			for( j = 0; j < i; j++ ) {
				int rc = ber_bvcmp( &mod->sm_bvalues[i],
					&mod->sm_bvalues[j] );

				if( rc == 0 ) {
					/* value exists already */
					*text = textbuf;
					snprintf( textbuf, textlen,
						"modify/%s: %s: value #%i already exists",
						op, mod->sm_desc->ad_cname.bv_val );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}
		}

	} else {
		for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
			int rc, match;
			struct berval asserted;

			rc = value_normalize( mod->sm_desc,
				SLAP_MR_EQUALITY,
				&mod->sm_bvalues[i],
				&asserted,
				text );

			if( rc != LDAP_SUCCESS ) return rc;

			if( a ) {
				for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
					int rc = value_match( &match, mod->sm_desc, mr,
						SLAP_MR_VALUE_SYNTAX_MATCH,
						&a->a_vals[j], &asserted, text );

					if( rc == LDAP_SUCCESS && match == 0 ) {
						free( asserted.bv_val );
						return LDAP_TYPE_OR_VALUE_EXISTS;
					}
				}
			}

			for ( j = 0; j < i; j++ ) {
				int rc = value_match( &match, mod->sm_desc, mr,
					SLAP_MR_VALUE_SYNTAX_MATCH,
					&mod->sm_bvalues[j], &asserted, text );

				if( rc == LDAP_SUCCESS && match == 0 ) {
					free( asserted.bv_val );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}

			free( asserted.bv_val );
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
	char *desc = mod->sm_desc->ad_cname.bv_val;
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;

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

void
slap_modlist_free(
    LDAPModList	*ml
)
{
	LDAPModList *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->ml_next;

		if (ml->ml_type)
			free( ml->ml_type );

		if ( ml->ml_bvalues != NULL )
			ber_bvecfree( ml->ml_bvalues );

		free( ml );
	}
}

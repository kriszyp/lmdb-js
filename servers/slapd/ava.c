/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ava.c - routines for dealing with attribute value assertions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"


void
ava_free(
	Operation *op,
	AttributeAssertion *ava,
	int	freeit
)
{
	op->o_tmpfree( ava->aa_value.bv_val, op->o_tmpmemctx );
	if ( freeit ) {
		op->o_tmpfree( (char *) ava, op->o_tmpmemctx );
	}
}

int
get_ava(
	Operation *op,
	BerElement	*ber,
	AttributeAssertion	**ava,
	unsigned usage,
	const char **text
)
{
	int rc;
	ber_tag_t rtag;
	struct berval type, value;
	AttributeAssertion *aa;

	rtag = ber_scanf( ber, "{mm}", &type, &value );

	if( rtag == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, ERR, "get_ava:  ber_scanf failure\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "  get_ava ber_scanf\n", 0, 0, 0 );
#endif
		*text = "Error decoding attribute value assertion";
		return SLAPD_DISCONNECT;
	}

	aa = op->o_tmpalloc( sizeof( AttributeAssertion ), op->o_tmpmemctx );
	aa->aa_desc = NULL;
	aa->aa_value.bv_val = NULL;

	rc = slap_bv2ad( &type, &aa->aa_desc, text );

	if( rc != LDAP_SUCCESS ) {
		op->o_tmpfree( aa, op->o_tmpmemctx );
		return rc;
	}

	rc = asserted_value_validate_normalize(
		aa->aa_desc, ad_mr(aa->aa_desc, usage),
		usage, &value, &aa->aa_value, text, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
		op->o_tmpfree( aa, op->o_tmpmemctx );
		return rc;
	}

	*ava = aa;

	return LDAP_SUCCESS;
}

/* str2filter.c - parse an rfc 1588 string filter */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "slap.h"
#include <ldap_pvt.h>

#if 0 /* unused */
static char	*find_matching_paren( const char *s );
#endif /* unused */
static Filter	*str2list( const char *str, long unsigned int ftype);
static Filter	*str2simple( const char *str);
static int	str2subvals( const char *val, Filter *f);

Filter *
str2filter_x( Operation *op, const char *str )
{
	int rc;
	Filter	*f = NULL;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	const char *text = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY,  "str2filter: \"%s\"\n", str, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "str2filter \"%s\"\n", str, 0, 0 );
#endif

	if ( str == NULL || *str == '\0' ) {
		return NULL;
	}

	ber_init2( ber, NULL, LBER_USE_DER );
	if ( op->o_tmpmemctx ) {
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );
	}

	rc = ldap_pvt_put_filter( ber, str );
	if( rc < 0 ) {
		goto done;
	}

	ber_reset( ber, 1 );

	rc = get_filter( op, ber, &f, &text );

done:
	ber_free_buf( ber );

	return f;
}

Filter *
str2filter( const char *str )
{
	Operation op = {0};

	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	return str2filter_x( &op, str );
}

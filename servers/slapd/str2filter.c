/* str2filter.c - parse an rfc 1588 string filter */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
str2filter( const char *str )
{
	int rc;
	Filter	*f = NULL;
	char berbuf[256];
	BerElement *ber = (BerElement *)berbuf;
	Connection conn;
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

	rc = ldap_pvt_put_filter( ber, str );
	if( rc < 0 ) {
		goto done;
	}

	ber_reset( ber, 1 );

	conn.c_connid = 0;

	rc = get_filter( &conn, ber, &f, &text );

done:
	ber_free_buf( ber );

	return f;
}

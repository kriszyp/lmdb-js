/* error.c - BDB errcall routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb.h"

void bdb_errcall( const char *pfx, char * msg )
{
#ifdef HAVE_EBCDIC
	if ( msg[0] > 0x7f )
		__etoa( msg );
#endif
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, INFO, "bdb(%s): %s\n", pfx, msg, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "bdb(%s): %s\n", pfx, msg, 0 );
#endif
}

#ifdef HAVE_EBCDIC

#undef db_strerror

/* Not re-entrant! */
char *ebcdic_dberror( int rc )
{
	static char msg[1024];

	strcpy( msg, db_strerror( rc ) );
	__etoa( msg );
	return msg;
}
#endif

/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <lber.h>
#include <lutil.h>
#include <ldap_defaults.h>

char* lutil_progname( const char* name, int argc, char *argv[] )
{
	char *progname;

	if(argc == 0) {
		return ber_strdup( name );
	}

	progname = strrchr ( argv[0], *LDAP_DIRSEP );
	progname = ber_strdup( progname ? &progname[1] : argv[0] );

	return progname;
}

#ifndef HAVE_MKSTEMP
int mkstemp( char * template )
{
#ifdef HAVE_MKTEMP
	return open ( mktemp ( template ), O_RDWR|O_CREAT|O_EXCL, 0600 );
#else
	return -1;
#endif
}
#endif

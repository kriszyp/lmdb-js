/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "lutil.h"

char *hash[] = {
	"{SMD5}", "{SSHA}",
	"{MD5}", "{SHA}",
	NULL
};

struct pwtable {
	char *pw;
	size_t pwlen;
};

static const struct pwtable pw[] = {
	{ "secret", sizeof("secret")-1 },
	{ "secret\0binary", sizeof("binary\0secret")-1 },
	{ NULL }
};

int
main( int argc, char *argv[] )
{
	int i, j, rc;
	char *passwd;

	for( i= 0; hash[i]; i++ ) {
		for( j = 0; pw[j].pw; j++ ) {
			passwd = lutil_passwd_generate( pw[j].pw, hash[i] );
			rc = lutil_passwd( passwd, pw[j].pw, NULL );

			printf("%s (%d): %s (%d)\n",
				pw[j].pw, pw[j].pwlen, passwd, rc );
		}
	}
	return EXIT_SUCCESS;
}
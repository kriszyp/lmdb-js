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

#include <lber.h>

#include "lutil.h"

/*
 * Password Test Program
 */

char *hash[] = {
	"{SMD5}", "{SSHA}",
	"{MD5}", "{SHA}",
#ifdef SLAPD_CRYPT
	"{CRYPT}",
#endif
	NULL
};

static struct berval pw[] = {
	{ sizeof("secret")-1,			"secret" },
	{ sizeof("binary\0secret")-1,	"secret\0binary" },
	{ 0, NULL }
};

int
main( int argc, char *argv[] )
{
	int i, j, rc;
	struct berval *passwd;

	for( i= 0; hash[i]; i++ ) {
		for( j = 0; pw[j].bv_len; j++ ) {
			passwd = lutil_passwd_hash( &pw[j], hash[i] );
			rc = lutil_passwd( passwd, &pw[j], NULL );

			printf("%s (%d): %s (%d) %s\n",
				pw[j].bv_val, pw[j].bv_len, passwd->bv_val, passwd->bv_len,
				rc == 0 ? "OKAY" : "BAD" );
		}
	}
	return EXIT_SUCCESS;
}
/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

#include <lutil.h>


int
slap_passwd_check(
	struct berval       **vals,
	struct berval       *v,
	int                 syntax,
	int                 normalize,
	struct berval		*cred
)
{
	int     i;
	for ( i = 0; vals[i] != NULL; i++ ) {
		if ( syntax == SYNTAX_BIN ) {
			int result;

#ifdef SLAPD_CRYPT
			ldap_pvt_thread_mutex_lock( &crypt_mutex );
#endif

			result = lutil_passwd(
				(char*) cred->bv_val,
				(char*) vals[i]->bv_val,
				NULL );

#ifdef SLAPD_CRYPT
			ldap_pvt_thread_mutex_unlock( &crypt_mutex );
#endif

			return result;

		} else {
                if ( value_cmp( vals[i], v, syntax, normalize ) == 0 ) {
                        return( 0 );
                }
        }
	}

	return( 1 );
}

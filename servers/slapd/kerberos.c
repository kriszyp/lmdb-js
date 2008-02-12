/* kerberos.c - ldbm backend kerberos bind routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"

#define LDAP_KRB_PRINCIPAL	"ldapserver"

krbv4_ldap_auth(
    Backend		*be,
    struct berval	*cred,
    AUTH_DAT		*ad
)
{
	KTEXT_ST        k;
	KTEXT           ktxt = &k;
	char            instance[INST_SZ];
	int             err;

	Debug( LDAP_DEBUG_TRACE, "=> kerberosv4_ldap_auth\n", 0, 0, 0 );

	if( cred->len > sizeof(ktxt->dat) ) {
		return LDAP_OTHER;
	}

	AC_MEMCPY( ktxt->dat, cred->bv_val, cred->bv_len );
	ktxt->length = cred->bv_len;

	strcpy( instance, "*" );
	if ( (err = krb_rd_req( ktxt, LDAP_KRB_PRINCIPAL, instance, 0L, ad,
	    ldap_srvtab )) != KSUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "krb_rd_req failed (%s)\n",
		    krb_err_txt[err], 0, 0 );
		return( LDAP_INVALID_CREDENTIALS );
	}

	return( LDAP_SUCCESS );
}

#endif /* kerberos */

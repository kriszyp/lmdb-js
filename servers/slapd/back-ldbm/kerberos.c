/* kerberos.c - ldbm backend kerberos bind routines */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

#ifdef KERBEROS
#ifdef KERBEROS_V
#include <kerberosIV/krb.h>
#else
#include <krb.h>
#endif /* KERBEROS_V */

#define LDAP_KRB_PRINCIPAL	"ldapserver"

extern char		*ldap_srvtab;
extern Attribute	*attr_find();

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

	SAFEMEMCPY( ktxt->dat, cred->bv_val, cred->bv_len );
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

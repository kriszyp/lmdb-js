/* bind.c - ldbm backend bind and unbind routines */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#ifdef KERBEROS
#include "krb.h"
#endif

extern Entry		*dn2entry();
extern Attribute	*attr_find();

#ifdef KERBEROS
extern int	krbv4_ldap_auth();
#endif

int
ldbm_back_bind(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    char		*dn,
    int			method,
    struct berval	*cred
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*e;
	Attribute	*a;
	int		rc;
	char		*matched = NULL;
#ifdef KERBEROS
	char		krbname[MAX_K_NAME_SZ + 1];
	AUTH_DAT	ad;
#endif

	if ( (e = dn2entry( be, dn, &matched )) == NULL ) {
		/* allow noauth binds */
		if ( method == LDAP_AUTH_SIMPLE && cred->bv_len == 0 ) {
			/*
			 * bind successful, but return 1 so we don't
			 * authorize based on noauth credentials
			 */
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
			rc = 1;
		} else if ( be_isroot_pw( be, dn, cred ) ) {
			/* front end will send result */
			rc = 0;
		} else {
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			    matched, NULL );
			rc = 1;
		}
		if ( matched != NULL ) {
			free( matched );
		}
		return( rc );
	}

	switch ( method ) {
	case LDAP_AUTH_SIMPLE:
		if ( cred->bv_len == 0 ) {
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
			return( 1 );
		} else if ( be_isroot_pw( be, dn, cred ) ) {
			/* front end will send result */
			return( 0 );
		}

		if ( (a = attr_find( e->e_attrs, "userpassword" )) == NULL ) {
			if ( be_isroot_pw( be, dn, cred ) ) {
				/* front end will send result */
				return( 0 );
			}
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			cache_return_entry( &li->li_cache, e );
			return( 1 );
		}

		if ( value_find( a->a_vals, cred, a->a_syntax, 0 ) != 0 ) {
			if ( be_isroot_pw( be, dn, cred ) ) {
				/* front end will send result */
				return( 0 );
			}
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
			    NULL, NULL );
			cache_return_entry( &li->li_cache, e );
			return( 1 );
		}
		break;

#ifdef KERBEROS
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( be, cred, &ad ) != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
			    NULL, NULL );
			cache_return_entry( &li->li_cache, e );
			return( 1 );
		}
		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
		    : "", ad.pinst, ad.prealm );
		if ( (a = attr_find( e->e_attrs, "krbname" )) == NULL ) {
			/*
			 * no krbName values present:  check against DN
			 */
			if ( strcasecmp( dn, krbname ) == 0 ) {
				break;
			}
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			cache_return_entry( &li->li_cache, e );
			return( 1 );
		} else {	/* look for krbName match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_vals, &krbval, a->a_syntax, 3 )
			    != 0 ) {
				send_ldap_result( conn, op,
				    LDAP_INVALID_CREDENTIALS, NULL, NULL );
				cache_return_entry( &li->li_cache, e );
				return( 1 );
			}
		}
		break;

	case LDAP_AUTH_KRBV42:
		send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
		cache_return_entry( &li->li_cache, e );
		return( 1 );
#endif

	default:
		send_ldap_result( conn, op, LDAP_STRONG_AUTH_NOT_SUPPORTED,
		    NULL, "auth method not supported" );
		cache_return_entry( &li->li_cache, e );
		return( 1 );
	}

	cache_return_entry( &li->li_cache, e );

	/* success:  front end will send result */
	return( 0 );
}

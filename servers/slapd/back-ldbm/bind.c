/* bind.c - ldbm backend bind and unbind routines */

#include "portable.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"
#ifdef KERBEROS
#ifdef KERBEROS_V
#include <kerberosIV/krb.h>
#else
#include <krb.h>
#endif /* KERBEROS_V */
#endif /* KERBEROS */

#ifdef LDAP_CRYPT
/* change for crypted passwords -- lukeh */
#ifdef __NeXT__
extern char *crypt (char *key, char *salt);
#else
#include <unistd.h>
#endif
#endif /* LDAP_CRYPT */

#ifdef LDAP_SHA1
#include <lutil_sha1.h>
#endif /* LDAP_SHA1 */
#ifdef LDAP_MD5
#include <lutil_md5.h>
#endif /* LDAP_MD5 */

#include <lutil.h>

extern Attribute	*attr_find();

#ifdef KERBEROS
extern int	krbv4_ldap_auth();
#endif

#ifdef LDAP_CRYPT
pthread_mutex_t crypt_mutex;

static int
crypted_value_find(
	struct berval       **vals,
	struct berval       *v,
	int                 syntax,
	int                 normalize,
	struct berval		*cred
)
{
	int     i;
	for ( i = 0; vals[i] != NULL; i++ ) {
		if ( syntax != SYNTAX_BIN && strncasecmp( "{CRYPT}",
			vals[i]->bv_val, (sizeof("{CRYPT}") - 1 ) ) == 0 ) {
				char *userpassword = vals[i]->bv_val + sizeof("{CRYPT}") - 1;
				pthread_mutex_lock( &crypt_mutex );
				if (strcmp(userpassword, crypt(cred->bv_val,
						userpassword)) == 0) {
					pthread_mutex_unlock( &crypt_mutex );
					return ( 0 );
				}
				pthread_mutex_unlock( &crypt_mutex );
#ifdef LDAP_MD5
		} else if ( syntax != SYNTAX_BIN && strncasecmp( "{MD5}",
			vals[i]->bv_val, (sizeof("{MD5}") - 1 ) ) == 0 ) {
				ldap_MD5_CTX MD5context;
				unsigned char MD5digest[20];
				char base64digest[29]; 	/* ceiling(sizeof(input)/3) * 4 + 1 */

				char *userpassword = vals[i]->bv_val + sizeof("{MD5}") - 1;

				ldap_MD5Init(&MD5context);
				ldap_MD5Update(&MD5context, cred->bv_val, strlen(cred->bv_val));
				ldap_MD5Final(MD5digest, &MD5context);

				if (b64_ntop(MD5digest, sizeof(MD5digest),
					base64digest, sizeof(base64digest)) < 0)
				{
					return ( 1 );
				}

				if (strcmp(userpassword, base64digest) == 0) {
					return ( 0 );
				}
#endif /* LDAP_MD5 */
#ifdef LDAP_SHA1
		} else if ( syntax != SYNTAX_BIN && strncasecmp( "{SHA}",
			vals[i]->bv_val, (sizeof("{SHA}") - 1 ) ) == 0 ) {
				ldap_SHA1_CTX SHA1context;
				unsigned char SHA1digest[20];
				char base64digest[29]; 	/* ceiling(sizeof(input)/3) * 4 + 1 */

				char *userpassword = vals[i]->bv_val + sizeof("{SHA}") - 1;

				ldap_SHA1Init(&SHA1context);
				ldap_SHA1Update(&SHA1context, cred->bv_val, strlen(cred->bv_val));
				ldap_SHA1Final(SHA1digest, &SHA1context);

				if (b64_ntop(SHA1digest, sizeof(SHA1digest),
					base64digest, sizeof(base64digest)) < 0)
				{
					return ( 1 );
				}

				if (strcmp(userpassword, base64digest) == 0) {
					return ( 0 );
				}
#endif /* LDAP_SHA1 */
		} else {
                if ( value_cmp( vals[i], v, syntax, normalize ) == 0 ) {
                        return( 0 );
                }
        }
	}

	return( 1 );
}
#endif /* LDAP_CRYPT */

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

	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_bind: dn: %s\n", dn, 0, 0);

	/* get entry with reader lock */
	if ( (e = dn2entry_r( be, dn, &matched )) == NULL ) {
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
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, NULL );
			rc = 1;
		}
		if ( matched != NULL ) {
			free( matched );
		}
		return( rc );
	}

	/* check for deleted */

	switch ( method ) {
	case LDAP_AUTH_SIMPLE:
		if ( cred->bv_len == 0 ) {
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );

			/* stop front end from sending result */
			rc = 1;
			goto return_results;
		} else if ( be_isroot_pw( be, dn, cred ) ) {
			/* front end will send result */
			rc = 0;
			goto return_results;
		}

		if ( (a = attr_find( e->e_attrs, "userpassword" )) == NULL ) {
			if ( be_isroot_pw( be, dn, cred ) ) {
				/* front end will send result */
				rc = 0;
				goto return_results;
			}
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			rc = 1;
			goto return_results;
		}

#ifdef LDAP_CRYPT
		if ( crypted_value_find( a->a_vals, cred, a->a_syntax, 0, cred ) != 0 )
#else
		if ( value_find( a->a_vals, cred, a->a_syntax, 0 ) != 0 )
#endif
		{
			if ( be_isroot_pw( be, dn, cred ) ) {
				/* front end will send result */
				rc = 0;
				goto return_results;
			}
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
				NULL, NULL );
			rc = 1;
			goto return_results;
		}
		rc = 0;
		break;

#ifdef KERBEROS
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( be, cred, &ad ) != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
			    NULL, NULL );
			rc = 0;
			goto return_results;
		}
		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
		    : "", ad.pinst, ad.prealm );
		if ( (a = attr_find( e->e_attrs, "krbname" )) == NULL ) {
			/*
			 * no krbName values present:  check against DN
			 */
			if ( strcasecmp( dn, krbname ) == 0 ) {
				rc = 0; /* XXX wild ass guess */
				break;
			}
			send_ldap_result( conn, op, LDAP_INAPPROPRIATE_AUTH,
			    NULL, NULL );
			rc = 1;
			goto return_results;
		} else {	/* look for krbName match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_vals, &krbval, a->a_syntax, 3 ) != 0 ) {
				send_ldap_result( conn, op,
				    LDAP_INVALID_CREDENTIALS, NULL, NULL );
				rc = 1;
				goto return_results;
			}
		}
		break;

	case LDAP_AUTH_KRBV42:
		send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
		/* stop front end from sending result */
		rc = 1;
		goto return_results;
#endif

	default:
		send_ldap_result( conn, op, LDAP_STRONG_AUTH_NOT_SUPPORTED,
		    NULL, "auth method not supported" );
		rc = 1;
		goto return_results;
	}

return_results:;
	/* free entry and reader lock */
	cache_return_entry_r( &li->li_cache, e );

	/* front end with send result on success (rc==0) */
	return( rc );
}


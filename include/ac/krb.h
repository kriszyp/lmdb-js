/* Generic krb.h */

#ifndef _AC_KRB_H
#define _AC_KRB_H

#if defined( HAVE_KERBEROS )

#if defined( HAVE_KERBEROSIV_KRB_H )
#include <kerberosIV/krb.h>
#elif defined( HAVE_KRB_H )
#include <krb.h>
#endif

#if defined( HAVE_KERBEROSIV_DES_H )
#include <kerberosIV/des.h>
#elif defined( HAVE_DES_H )
#include <des.h>
#endif

#endif /* HAVE_KERBEROS */
#endif /* _AC_KRB_H */

/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>

#include <quipu/bind.h>
#if ISODEPACKAGE == IC
#include <quipu/DAS-types.h>
#else
#include <pepsy/DAS-types.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "common.h"

int
kerberosv4_ldap_auth( char *cred, long	len )
{
	KTEXT_ST	k;
	KTEXT		ktxt = &k;
	char		instance[INST_SZ];
	int		err;
	AUTH_DAT	ad;

	Debug( LDAP_DEBUG_TRACE, "kerberosv4_ldap_auth\n", 0, 0, 0 );

	SAFEMEMCPY( ktxt->dat, cred, len );
	ktxt->length = len;

	strcpy( instance, "*" );
	if ( (err = krb_rd_req( ktxt, krb_ldap_service, instance, 0L,
	    &ad, kerberos_keyfile )) != KSUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "krb_rd_req failed (%s)\n",
		    krb_err_txt[err], 0, 0 );
		return( LDAP_INVALID_CREDENTIALS );
	}

	return( LDAP_SUCCESS );
}

int
kerberosv4_bindarg( 
    struct ds_bind_arg	*ba,
    DN			dn,
    char		*cred,
    long		len,
    u_long		*nonce
)
{
	struct type_UNIV_EXTERNAL	*e;
	struct kerberos_parms		kp;
	PE				pe;
	struct timeval			tv;
	char				realm[REALM_SZ];
	int				err;

	Debug( LDAP_DEBUG_TRACE, "kerberosv4_bindarg\n", 0, 0, 0 );

	e = (struct type_UNIV_EXTERNAL *) calloc( 1,
	    sizeof(struct type_UNIV_EXTERNAL) );
	e->encoding = (struct choice_UNIV_0 *) calloc( 1,
	    sizeof(struct choice_UNIV_0) );
	ba->dba_external = e;
	ba->dba_version = DBA_VERSION_V1988;
	ba->dba_auth_type = DBA_AUTH_EXTERNAL;

	e->indirect__reference = AUTH_TYPE_KERBEROS_V4;
	e->direct__reference = NULLOID;
	e->data__value__descriptor = str2qb( "KRBv4 client credentials",
	    24, 1 );

	kp.kp_dn = dn;
	kp.kp_version = AUTH_TYPE_KERBEROS_V4;

	if ( (err = krb_get_lrealm( realm, 1 )) != KSUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "krb_get_lrealm failed (%s)\n",
		    krb_err_txt[err], 0, 0 );
		return( LDAP_OPERATIONS_ERROR );
	}

	gettimeofday( &tv, NULL );
	*nonce = tv.tv_sec;
	SAFEMEMCPY( kp.kp_ktxt.dat, cred, len );
	kp.kp_ktxt.length = len;
	if ( encode_kerberos_parms( &pe, &kp ) == NOTOK ) {
		Debug( LDAP_DEBUG_ANY, "kerberos parms encoding failed\n", 0,
		    0, 0 );
		return( LDAP_OPERATIONS_ERROR );
	}

	e->encoding->offset = choice_UNIV_0_single__ASN1__type;
	e->encoding->un.single__ASN1__type = pe;

	return( 0 );
}

int
kerberos_check_mutual(
    struct ds_bind_arg	*res,
    u_long		nonce
)
{
	struct type_UNIV_EXTERNAL	*e = res->dba_external;
	struct kerberos_parms		*kp;
	int				ret;

	Debug( LDAP_DEBUG_TRACE, "kerberos_check_mutual\n", 0, 0, 0 );

	if ( decode_kerberos_parms( e->encoding->un.single__ASN1__type, &kp )
	    == NOTOK )
		return( NOTOK );
	ret = ((kp->kp_nonce == (nonce + 1)) ? OK : NOTOK );

	Debug( LDAP_DEBUG_TRACE, "expecting %d got %d\n", nonce, kp->kp_nonce,
	    0 );

	pe_free( e->encoding->un.single__ASN1__type );
	dn_free( kp->kp_dn );
	free( (char *) kp );

	return( ret );
}

#endif

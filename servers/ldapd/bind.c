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

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>		/* get SAFEMEMCPY */

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/bind.h>
#include <quipu/compare.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef LDAP_COMPAT20
#define BINDTAG	(ldap_compat == 20 ? OLD_LDAP_RES_BIND : LDAP_RES_BIND)
#else
#define BINDTAG	LDAP_RES_BIND
#endif

/*
 * do_bind - perform an X.500 bind operation.  Since we always respond
 * to the request in here, always return 0 to signify the incoming message
 * can be discarded.
 */

int
do_bind( 
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber,
    int		*bound
)
{
	int		err;
	unsigned long	method;
	unsigned long	len;
	char		*dn, *pw;
	char		*matched;
	struct PSAPaddr	*addr;

	Debug( LDAP_DEBUG_TRACE, "do_bind\n", 0, 0, 0 );

	/*
	 * Parse the bind request.  It looks like this:
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,		 -- version
	 *		name		DistinguishedName,	 -- dn
	 *		authentication	CHOICE {
	 *			simple		[0] OCTET STRING -- passwd
	 *			krbv42ldap	[1] OCTET STRING
	 *			krbv42dsa	[1] OCTET STRING
	 *		}
	 *	}
	 */

	if ( ber_scanf( ber, "{ia", &version, &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, BINDTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "Decoding error" );
		return( 0 );
	}
#ifdef LDAP_COMPAT30
	if ( ldap_compat == 30 )
		method = ber_skip_tag( ber, &len );
	else
#endif
		method = ber_peek_tag( ber, &len );

	if ( ber_scanf( ber, "la}", &len, &pw ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf2 failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, BINDTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "Decoding error" );
		return( 0 );
	}

	if ( version != LDAP_VERSION1 && version != LDAP_VERSION2 ) {
		Debug( LDAP_DEBUG_ANY, "unknown version %d\n", version, 0, 0 );
		send_ldap_msgresult( clientsb, BINDTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "Version not supported" );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_bind: version %d dn (%s) method %lu\n",
	    version, dn, method );

	if ( m->m_conn->c_paddr == NULLPA ) {
		char	buf[256];

		sprintf( buf, "Bad DSA address (%s)", dsa_address ?
		    dsa_address : "NULL" );
		send_ldap_msgresult( clientsb, BINDTAG, m,
		    LDAP_OPERATIONS_ERROR, NULL, buf );
		return( 0 );
	}

	if ( m->m_conn->c_dn )
		free( m->m_conn->c_dn );
	if ( m->m_conn->c_cred )
		free( m->m_conn->c_cred );
	m->m_conn->c_dn = dn;
	m->m_conn->c_cred = pw;
	m->m_conn->c_credlen = len;
	m->m_conn->c_method = method;

	err = do_bind_real( m->m_conn, bound, &matched );

	send_ldap_msgresult( clientsb, BINDTAG, m, err, matched, "" );

	if ( matched != NULL )
		free( matched );

	return( 0 );
}

int
do_bind_real(
    struct conn	*dsaconn,
    int		*bound,
    char	**matched
)
{
	struct ds_bind_arg	ba;
	struct ds_bind_arg	br;
	struct ds_bind_error	be;
	struct DSError		dse;
	char			*dn = dsaconn->c_dn;
	int			err;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	u_long			nonce;
#endif
	Debug( LDAP_DEBUG_TRACE, "do_bind_real\n", 0, 0, 0 );

	*matched = NULL;
	if ( (ba.dba_dn = ldap_str2dn( dn )) == NULLDN && *dn != '\0' ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn (%s) failed\n", dn, 0, 0 );
		return( LDAP_INVALID_DN_SYNTAX );
	}

	switch ( dsaconn->c_method ) {
#ifdef LDAP_COMPAT20
	case OLD_LDAP_AUTH_SIMPLE:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_AUTH_SIMPLE_30:
#endif
	case LDAP_AUTH_SIMPLE:	/* x.500 simple authentication */
		if ( dsaconn->c_credlen > DBA_MAX_PASSWD_LEN ) {
			Debug( LDAP_DEBUG_ANY, "Password too long\n", 0, 0, 0 );
			return( LDAP_INAPPROPRIATE_AUTH );
		}
		if (( ba.dba_passwd_len = dsaconn->c_credlen ) > 0 ) {
			SAFEMEMCPY( ba.dba_passwd, dsaconn->c_cred,
			    ba.dba_passwd_len );
			ba.dba_auth_type = DBA_AUTH_SIMPLE;
		} else {
			ba.dba_auth_type = DBA_AUTH_NONE;
		}
		ba.dba_version = DBA_VERSION_V1988;
		break;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
#ifdef LDAP_COMPAT20
	case OLD_LDAP_AUTH_KRBV4:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_AUTH_KRBV41_30:
#endif
	case LDAP_AUTH_KRBV41:	/* kerberos authentication to ldap server */
		return( kerberosv4_ldap_auth( dsaconn->c_cred,
		    dsaconn->c_credlen ) );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_AUTH_KRBV42:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_AUTH_KRBV42_30:
#endif
	case LDAP_AUTH_KRBV42:	/* kerberos authentication to x500 dsa */
		if ( (err = kerberosv4_bindarg( &ba, ba.dba_dn, dsaconn->c_cred,
		    dsaconn->c_credlen, &nonce )) != 0 )
			return( err );
		break;
#endif

	default:
		return( LDAP_PROTOCOL_ERROR );
		break;
	}

	if ( dsaconn->c_ad != -1 )
		dap_unbind( dsaconn->c_ad );

	Debug( LDAP_DEBUG_TRACE, "dap_bind to dsa (%s)...\n", paddr2str(
	    dsaconn->c_paddr, NULLNA ), 0, 0 );

	err = dap_bind( &dsaconn->c_ad, &ba, &be, &br, dsaconn->c_paddr );

	if ( err != DS_OK && ba.dba_dn != NULLDN && ba.dba_auth_type
	    == DBA_AUTH_NONE && be.dbe_type == DBE_TYPE_SECURITY ) {
		/* if doing a NULL bind, retry with a NULL dn */
		Debug( LDAP_DEBUG_TRACE, "retring NULL dap_bind\n", 0, 0, 0 );
		dn_free( ba.dba_dn );
		ba.dba_dn = NULLDN;
		err = dap_bind( &dsaconn->c_ad, &ba, &be, &br,
		    dsaconn->c_paddr );
	}

	if ( err != DS_OK ) {
		if ( ba.dba_dn != NULLDN )
			dn_free( ba.dba_dn );

		if ( be.dbe_type == DBE_TYPE_SERVICE ) {
			dse.dse_type = DSE_SERVICEERROR;
			dse.ERR_SERVICE.DSE_sv_problem = be.dbe_value;
		} else if ( be.dbe_type == DBE_TYPE_SECURITY ) {
			dse.dse_type = DSE_SECURITYERROR;
			dse.ERR_SECURITY.DSE_sc_problem = be.dbe_value;
		} else {
			dse.dse_type = DSE_REMOTEERROR;
		}
		err = x500err2ldaperr( &dse, matched );

#ifdef LDAP_DEBUG
		if ( ldap_debug )
			print_error( &dse );	/* prints and then frees */
		else
#endif
			ds_error_free( &dse );

		dsaconn->c_ad = -1;

		return( err );
	}
	bind_arg_free( &br );

	Debug( LDAP_DEBUG_TRACE, "dap_bind successful\n", 0, 0, 0 );

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
/* XXX why doesn't this work??
	if ( dsaconn->c_method == LDAP_AUTH_KRBV42 &&
	    kerberos_check_mutual( &br, nonce ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "Mutual authentication failed\n", 0, 0,
		    0 );
		return( LDAP_INVALID_CREDENTIALS );
	}
*/
#endif

	*bound = 1;

	return( LDAP_SUCCESS );
}

/* $OpenLDAP$ */
/*
 *	 Copyright 1999, John C. Quillan, All rights reserved.
 *	 Portions Copyright 2002, myinternet Limited. All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"
/* init.c - initialize Perl backend */
	
#include <stdio.h>

#include "slap.h"
#ifdef HAVE_WIN32_ASPERL
#include "asperl_undefs.h"
#endif

#include <EXTERN.h>
#include <perl.h>

#include "perl_back.h"


/**********************************************************
 *
 * Bind
 *
 **********************************************************/
int
perl_back_bind(
	Backend *be,
	Connection *conn,
	Operation *op,
	struct berval *dn,
	struct berval *ndn,
	int method,
	struct berval *cred,
	struct berval *edn
)
{
	int return_code;
	int count;

	PerlBackend *perl_back = (PerlBackend *) be->be_private;

#ifdef HAVE_WIN32_ASPERL
	PERL_SET_CONTEXT( PERL_INTERPRETER );
#endif

	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	{
		dSP; ENTER; SAVETMPS;

		PUSHMARK(SP);
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( dn->bv_val , 0)));
		XPUSHs(sv_2mortal(newSVpv( cred->bv_val , cred->bv_len)));
		PUTBACK;

#ifdef PERL_IS_5_6
		count = call_method("bind", G_SCALAR);
#else
		count = perl_call_method("bind", G_SCALAR);
#endif

		SPAGAIN;

		if (count != 1) {
			croak("Big trouble in back_bind\n");
		}

		return_code = POPi;
							 

		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );	

	Debug( LDAP_DEBUG_ANY, "Perl BIND returned 0x%04x\n", return_code, 0, 0 );

	/* frontend will send result on success (0) */
	if( return_code != LDAP_SUCCESS )
		send_ldap_result( conn, op, return_code, NULL, NULL, NULL, NULL );

	return ( return_code );
}

/* $OpenLDAP$ */
/*
 *	 Copyright 1999, John C. Quillan, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#include <stdio.h>
/*	#include <ac/types.h>
	#include <ac/socket.h>
*/

#include <EXTERN.h>
#include <perl.h>

#include "slap.h"
#include "perl_back.h"

/**********************************************************
 *
 * Compare
 *
 **********************************************************/

perl_back_compare(
	Backend	*be,
	Connection	*conn,
	Operation	*op,
	const char	*dn,
	const char	*ndn,
	Ava		*ava
)
{
	int return_code;
	int count;

	PerlBackend *perl_back = (PerlBackend *)be->be_private;

	send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
		NULL, "not supported", NULL, NULL );

#ifdef notdef
	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	{
		dSP; ENTER; SAVETMPS;

		PUSHMARK(sp);
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( dn , 0)));
		/* XPUSHs(sv_2mortal(newSVpv( cred->bv_val , cred->bv_len))); */
		PUTBACK;

		count = perl_call_method("bind", G_SCALAR);

		SPAGAIN;

		if (count != 1) {
			croak("Big trouble in back_search\n");
		}

		return_code = POPi;
							 
		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );	

	if( return_code != 0 ) {
		send_ldap_result( conn, op, LDAP_COMPARE_TRUE, NULL, NULL );

	} else {
		send_ldap_result( conn, op, LDAP_COMPARE_FALSE, NULL, NULL );
	}
#endif

	Debug( LDAP_DEBUG_ANY, "Here BIND\n", 0, 0, 0 );

	return (0);
}


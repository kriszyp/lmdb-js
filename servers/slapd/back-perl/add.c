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

#include <stdio.h>

#include "slap.h"
#ifdef HAVE_WIN32_ASPERL
#include "asperl_undefs.h"
#endif

#include <EXTERN.h>
#include <perl.h>

#include "perl_back.h"

int
perl_back_add(
	Backend	*be,
	Connection	*conn,
	Operation	*op,
	Entry	*e
)
{
	int len;
	int count;
	int return_code;

	PerlBackend *perl_back = (PerlBackend *) be->be_private;

	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );
	ldap_pvt_thread_mutex_lock( &entry2str_mutex );

	{
		dSP; ENTER; SAVETMPS;

		PUSHMARK(sp);
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( entry2str( e, &len ), 0 )));

		PUTBACK;

#ifdef PERL_IS_5_6
		count = call_method("add", G_SCALAR);
#else
		count = perl_call_method("add", G_SCALAR);
#endif

		SPAGAIN;

		if (count != 1) {
			croak("Big trouble in back_add\n");
		}
							 
		return_code = POPi;

		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );
	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );	

	send_ldap_result( conn, op, return_code,
		NULL, NULL, NULL, NULL );

	Debug( LDAP_DEBUG_ANY, "Perl ADD\n", 0, 0, 0 );
	return( 0 );
}

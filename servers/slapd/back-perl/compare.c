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

/**********************************************************
 *
 * Compare
 *
 **********************************************************/

int
perl_back_compare(
	Backend	*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn,
	AttributeAssertion		*ava
)
{
	int return_code;
	int count;
	char *avastr, *ptr;

	PerlBackend *perl_back = (PerlBackend *)be->be_private;

	avastr = ch_malloc( ava->aa_desc->ad_cname.bv_len + 1 +
		ava->aa_value.bv_len + 1 );
	
	lutil_strcopy( lutil_strcopy( lutil_strcopy( avastr,
		ava->aa_desc->ad_cname.bv_val ), "=" ),
		ava->aa_value.bv_val );

	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	{
		dSP; ENTER; SAVETMPS;

		PUSHMARK(sp);
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( dn->bv_val , 0)));
		XPUSHs(sv_2mortal(newSVpv( avastr , 0)));
		PUTBACK;

#ifdef PERL_IS_5_6
		count = call_method("compare", G_SCALAR);
#else
		count = perl_call_method("compare", G_SCALAR);
#endif

		SPAGAIN;

		if (count != 1) {
			croak("Big trouble in back_compare\n");
		}

		return_code = POPi;
							 
		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );	

	ch_free( avastr );

	send_ldap_result( conn, op, return_code,
		NULL, NULL, NULL, NULL );

	Debug( LDAP_DEBUG_ANY, "Perl COMPARE\n", 0, 0, 0 );

	return (0);
}


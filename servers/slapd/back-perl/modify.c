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
/* #include <ac/types.h>
	#include <ac/socket.h>
*/

#include <EXTERN.h>
#include <perl.h>

#include "slap.h"
#include "perl_back.h"

int
perl_back_modify(
	Backend	*be,
	Connection	*conn,
	Operation	*op,
	const char	*dn,
	const char	*ndn,
	LDAPModList	*modlist
)
{
	char test[500];
	int return_code;
	int count;
	int i;
	int err = 0;
	char *matched = NULL, *info = NULL;

	PerlBackend *perl_back = (PerlBackend *)be->be_private;

	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	{
		dSP; ENTER; SAVETMPS;
		
		PUSHMARK(sp);
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( dn , 0)));

		for (; modlist != NULL; modlist = modlist->ml_next ) {
			LDAPMod *mods = &modlist->ml_mod;

			switch ( mods->mod_op & ~LDAP_MOD_BVALUES ) {
			case LDAP_MOD_ADD:
				XPUSHs(sv_2mortal(newSVpv("ADD", 0 )));
				break;
				
			case LDAP_MOD_DELETE:
				XPUSHs(sv_2mortal(newSVpv("DELETE", 0 )));
				break;
				
			case LDAP_MOD_REPLACE:
				XPUSHs(sv_2mortal(newSVpv("REPLACE", 0 )));
				break;
			}

			
			XPUSHs(sv_2mortal(newSVpv( mods->mod_type, 0 )));

			for ( i = 0;
				mods->mod_bvalues != NULL && mods->mod_bvalues[i] != NULL;
				i++ )
			{
				XPUSHs(sv_2mortal(newSVpv( mods->mod_bvalues[i]->bv_val, 0 )));
			}
		}

		PUTBACK;

		count = perl_call_method("modify", G_SCALAR);

		SPAGAIN;

		if (count != 1) {
			croak("Big trouble in back_search\n");
		}
							 
		return_code = POPi;

		PUTBACK; FREETMPS; LEAVE;
	}

	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );

	if( return_code != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );

	} else {
		send_ldap_result( conn, op, LDAP_SUCCESS,
			NULL, NULL, NULL, NULL );
	}

	Debug( LDAP_DEBUG_ANY, "Perl MODIFY\n", 0, 0, 0 );
	return( 0 );
}


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
 * Search
 *
 **********************************************************/
int
perl_back_search(
	Backend *be,
	Connection *conn,
	Operation *op,
	char *base,
	char *nbase,
	int scope,
	int deref,
	int sizelimit,
	int timelimit,
	Filter *filter,
	char *filterstr,
	char **attrs,
	int attrsonly
	)
{
	char test[500];
	int count ;
	int err = 0;
	char *matched = NULL, *info = NULL;
	PerlBackend *perl_back = (PerlBackend *)be->be_private;
	Entry	*e;
	char *buf;
	int i;
	int return_code;

	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	{
		dSP; ENTER; SAVETMPS;

		PUSHMARK(sp) ;
		XPUSHs( perl_back->pb_obj_ref );
		XPUSHs(sv_2mortal(newSVpv( filterstr , 0)));
		XPUSHs(sv_2mortal(newSViv( sizelimit )));
		XPUSHs(sv_2mortal(newSViv( timelimit )));
		XPUSHs(sv_2mortal(newSViv( attrsonly )));

		for ( i = 0; attrs != NULL && attrs[i] != NULL; i++ ) {
			XPUSHs(sv_2mortal(newSVpv( attrs[i] , 0)));
		}
		PUTBACK;

		count = perl_call_method("search", G_ARRAY );

		SPAGAIN;

		if (count < 1) {
			croak("Big trouble in back_search\n") ;
		}

		if ( count > 1 ) {
							 
			for ( i = 1; i < count; i++ ) {

				buf = POPp;

				if ( (e = str2entry( buf )) == NULL ) {
					Debug( LDAP_DEBUG_ANY, "str2entry(%s) failed\n", buf, 0, 0 );

				} else {
					send_search_entry( be, conn, op,
						e, attrs, attrsonly, NULL );
							 
					entry_free( e );
				}
			}
		}

		/*
		 * We grab the return code last because the stack comes
		 * from perl in reverse order. 
		 *
		 * ex perl: return ( 0, $res_1, $res_2 );
		 *
		 * ex stack: <$res_2> <$res_1> <0>
		 */

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
}


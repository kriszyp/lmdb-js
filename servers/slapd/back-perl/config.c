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
/* init.c - initialize shell backend */
	
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
 * Config
 *
 **********************************************************/
int
perl_back_db_config(
	 BackendDB *be,
	 const char *fname,
	 int lineno,
	 int argc,
	 char **argv
)
{
	SV* loc_sv;
	PerlBackend *perl_back = (PerlBackend *) be->be_private;
	char eval_str[EVAL_BUF_SIZE];
	int count ;
	int args;
	int return_code;
	

	if ( strcasecmp( argv[0], "perlModule" ) == 0 ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
				 "%s.pm: line %d: missing module in \"perlModule <module>\" line\n",
				fname, lineno, 0 );
			return( 1 );
		}

		strncpy(eval_str, argv[1], EVAL_BUF_SIZE );

		perl_require_pv( strcat( eval_str, ".pm" ));

		if (SvTRUE(GvSV(errgv))) {
			fprintf(stderr , "Error %s\n", SvPV(GvSV(errgv), na)) ;

		} else {
			dSP; ENTER; SAVETMPS;
			PUSHMARK(sp);
			XPUSHs(sv_2mortal(newSVpv(argv[1], 0)));
			PUTBACK;

			count = perl_call_method("new", G_SCALAR);
			
			SPAGAIN;

			if (count != 1) {
				croak("Big trouble in config\n") ;
			}

			perl_back->pb_obj_ref = newSVsv(POPs);

			PUTBACK; FREETMPS; LEAVE ;
		}

	} else if ( strcasecmp( argv[0], "perlModulePath" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
				"%s: line %d: missing module in \"PerlModulePath <module>\" line\n",
				fname, lineno );
			return( 1 );
		}

		sprintf( eval_str, "push @INC, '%s';", argv[1] );
		loc_sv = perl_eval_pv( eval_str, 0 );

	} else {
		/*
		 * Pass it to Perl module if defined
		 */

		{
			dSP ;  ENTER ; SAVETMPS;

			PUSHMARK(sp) ;
			XPUSHs( perl_back->pb_obj_ref );

			/* Put all arguments on the perl stack */
			for( args = 0; args < argc; args++ ) {
				XPUSHs(sv_2mortal(newSVpv(argv[args], 0)));
			}

			PUTBACK ;

			count = perl_call_method("config", G_SCALAR);

			SPAGAIN ;

			if (count != 1) {
				croak("Big trouble in config\n") ;
			}

			return_code = POPi;

			PUTBACK ; FREETMPS ;  LEAVE ;

		}

		/* if the module rejected it then we should reject it */
		if ( return_code != 0 ) {
			fprintf( stderr,
				 "Unknown perl backeng config: %s\n", argv[0]);
			exit( EXIT_FAILURE );
		}
	}

	return 0;
}

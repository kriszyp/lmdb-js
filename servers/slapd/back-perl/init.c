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
/* #include <ac/types.h>
	#include <ac/socket.h>
*/

#include <EXTERN.h>
#include <perl.h>


#include "slap.h"
#include "perl_back.h"


PerlInterpreter *perl_interpreter = NULL;
pthread_mutex_t	perl_interpreter_mutex;


/**********************************************************
 *
 * Init
 *
 **********************************************************/

void
perl_back_init(
	Backend	*be
)
{
	char *embedding[] = { "", "-e", "0" };

	if( perl_interpreter == NULL ) {
		perl_interpreter = perl_alloc();
		perl_construct(perl_interpreter);
		perl_parse(perl_interpreter, NULL, 3, embedding, (char **)NULL);
		perl_run(perl_interpreter);
		
		pthread_mutex_init( &perl_interpreter_mutex,
			pthread_mutexattr_default );
	}

	be->be_private = (PerlBackend *) ch_malloc( sizeof(PerlBackend) );
	memset(&be->be_private, 0, sizeof(PerlBackend));

	Debug( LDAP_DEBUG_ANY, "Here in perl backend\n", 0, 0, 0 );
}


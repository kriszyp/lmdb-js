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
 * Close
 *
 **********************************************************/

int
perl_back_close(
	BackendInfo *bd
)
{
	ldap_pvt_thread_mutex_lock( &perl_interpreter_mutex );	

	perl_destruct(perl_interpreter);

	ldap_pvt_thread_mutex_unlock( &perl_interpreter_mutex );	

	return 0;
}

int
perl_back_destroy(
	BackendInfo *bd
)
{
	perl_free(perl_interpreter);
	perl_interpreter = NULL;

	ldap_pvt_thread_mutex_destroy( &perl_interpreter_mutex );	

	return 0;
}

int
perl_back_db_destroy(
	BackendDB *be
)
{
	free( be->be_private );
	be->be_private = NULL;
}

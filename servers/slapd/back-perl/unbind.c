/* $OpenLDAP$ */
/*
 *   Copyright 1999, John C. Quillan, All rights reserved.
 *
 *   Redistribution and use in source and binary forms are permitted only
 *   as authorized by the OpenLDAP Public License.  A copy of this
 *   license is available at http://www.OpenLDAP.org/license.html or
 *   in file LICENSE in the top-level directory of the distribution.
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
 * UnBind
 *
 **********************************************************/
int
perl_back_unbind(
	Backend *be,
	Connection *conn,
	Operation *op
)
{
	Debug( LDAP_DEBUG_TRACE, "Perl UNBIND\n", 0, 0, 0 );
	return 0;
}


/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#include <stdio.h>
#include <stdarg.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "ldap_pvt_thread.h"


/*
 * Common LDAP thread routines
 *	see thr_*.c for implementation specific routines
 *	see rdwr.c for generic reader/writer lock implementation
 *	see tpool.c for generic thread pool implementation
 */


int ldap_pvt_thread_initialize( void )
{
	int rc;
	static int init = 0;

	/* we only get one shot at this */
	if( init++ ) return -1;

	rc = ldap_int_thread_initialize();
	if( rc ) return rc;

#ifndef LDAP_THREAD_HAVE_TPOOL
	rc = ldap_int_thread_pool_startup();
	if( rc ) return rc;
#endif

	return 0;
}

int ldap_pvt_thread_destroy( void )
{
#ifndef LDAP_THREAD_HAVE_TPOOL
	(void) ldap_int_thread_pool_shutdown();
#endif
	return ldap_int_thread_destroy();
}

#ifndef LDAP_THREAD_HAVE_GETCONCURRENCY
int
ldap_pvt_thread_get_concurrency ( void )
{
	return 1;
}
#endif

#ifndef LDAP_THREAD_HAVE_SETCONCURRENCY
int
ldap_pvt_thread_set_concurrency ( int concurrency )
{
	return 1;
}
#endif

#ifndef LDAP_THREAD_HAVE_SLEEP
/*
 * Here we assume we have fully preemptive threads and that sleep()
 * does the right thing.
 */
unsigned int
ldap_pvt_thread_sleep(
	unsigned int interval
)
{
	sleep( interval );
	return 0;
}
#endif

/* trans.c - bdb backend transaction routines */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"
#include "lber_pvt.h"


/* Congestion avoidance code
 * for Deadlock Rollback
 */

void
bdb_trans_backoff( int num_retries )
{
	int i;
	int delay = 0;
	int pow_retries = 1;
	unsigned long key = 0;
	unsigned long max_key = -1;
	struct timeval timeout;

	lutil_entropy( &key, sizeof( unsigned long ));

	for ( i = 0; i < num_retries; i++ ) {
		if ( i >= 5 ) break;
		pow_retries *= 4;
	}

	delay = 16384 * (key * (double) pow_retries / (double) max_key);
	delay = delay ? delay : 1;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ERR, "delay = %d, num_retries = %d\n", delay, num_retries, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,  "delay = %d, num_retries = %d\n", delay, num_retries, 0 );
#endif

	timeout.tv_sec = delay / 1000000;
	timeout.tv_usec = delay % 1000000;
	select( 0, NULL, NULL, NULL, &timeout );
}

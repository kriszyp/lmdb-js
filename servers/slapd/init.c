/* init.c - initialize various things */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "lber_pvt.h"

/*
 * read-only global variables or variables only written by the listener
 * thread (after they are initialized) - no need to protect them with a mutex.
 */
int		slap_debug = 0;

#ifdef LDAP_DEBUG
int		ldap_syslog = LDAP_DEBUG_STATS;
#else
int		ldap_syslog;
#endif

#ifdef LOG_DEBUG
int		ldap_syslog_level = LOG_DEBUG;
#endif

BerVarray default_referral = NULL;

struct berval AllUser = BER_BVC( LDAP_ALL_USER_ATTRIBUTES );
struct berval AllOper = BER_BVC( LDAP_ALL_OPERATIONAL_ATTRIBUTES );
struct berval NoAttrs = BER_BVC( LDAP_NO_ATTRS );

/*
 * global variables that need mutex protection
 */
ldap_pvt_thread_pool_t	connection_pool;
int			connection_pool_max = SLAP_MAX_WORKER_THREADS;
ldap_pvt_thread_mutex_t	gmtime_mutex;
#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
ldap_pvt_thread_mutex_t	passwd_mutex;
#endif

unsigned long			num_ops_initiated = 0;
unsigned long			num_ops_completed = 0;
#ifdef SLAPD_MONITOR
unsigned long			num_ops_initiated_[SLAP_OP_LAST];
unsigned long			num_ops_completed_[SLAP_OP_LAST];
#endif /* SLAPD_MONITOR */
ldap_pvt_thread_mutex_t	num_ops_mutex;

unsigned long			num_entries_sent;
unsigned long			num_refs_sent;
unsigned long			num_bytes_sent;
unsigned long			num_pdu_sent;
ldap_pvt_thread_mutex_t	num_sent_mutex;
/*
 * these mutexes must be used when calling the entry2str()
 * routine since it returns a pointer to static data.
 */
ldap_pvt_thread_mutex_t	entry2str_mutex;
ldap_pvt_thread_mutex_t	replog_mutex;

static const char* slap_name = NULL;
int slapMode = SLAP_UNDEFINED_MODE;

/*
 * all known control OIDs should be added to this list
 */
char *slap_known_controls[] = {
#ifdef LDAP_CONTROL_REFERRALS
	LDAP_CONTROL_REFERRALS,
#endif /* LDAP_CONTROL_REFERRALS */

	LDAP_CONTROL_MANAGEDSAIT,

#ifdef LDAP_CONTROL_SUBENTRIES
	LDAP_CONTROL_SUBENTRIES,
#endif /* LDAP_CONTROL_SUBENTRIES */

	LDAP_CONTROL_NOOP,

#ifdef LDAP_CONTROL_DUPENT_REQUEST
	LDAP_CONTROL_DUPENT_REQUEST,
#endif /* LDAP_CONTROL_DUPENT_REQUEST */

#ifdef LDAP_CONTROL_DUPENT_RESPONSE
	LDAP_CONTROL_DUPENT_RESPONSE,
#endif /* LDAP_CONTROL_DUPENT_RESPONSE */

#ifdef LDAP_CONTROL_DUPENT_ENTRY
	LDAP_CONTROL_DUPENT_ENTRY,
#endif /* LDAP_CONTROL_DUPENT_ENTRY */

	LDAP_CONTROL_PAGEDRESULTS,

#ifdef LDAP_CONTROL_SORTREQUEST
	LDAP_CONTROL_SORTREQUEST,
#endif /* LDAP_CONTROL_SORTREQUEST */

#ifdef LDAP_CONTROL_SORTRESPONSE
	LDAP_CONTROL_SORTRESPONSE,
#endif /* LDAP_CONTROL_SORTRESPONSE */

#ifdef LDAP_CONTROL_VLVREQUEST
	LDAP_CONTROL_VLVREQUEST,
#endif /* LDAP_CONTROL_VLVREQUEST */

#ifdef LDAP_CONTROL_VLVRESPONSE
	LDAP_CONTROL_VLVRESPONSE,
#endif /* LDAP_CONTROL_VLVRESPONSE */

	LDAP_CONTROL_VALUESRETURNFILTER,
	NULL
};

int
slap_init( int mode, const char *name )
{
	int rc;

	assert( mode );

	if( slapMode != SLAP_UNDEFINED_MODE ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT, 
			"init: %s init called twice (old=%d, new=%d)\n",
			name, slapMode, mode );
#else
		Debug( LDAP_DEBUG_ANY,
		 "%s init: init called twice (old=%d, new=%d)\n",
		 name, slapMode, mode );
#endif

		return 1;
	}

	slapMode = mode;

	switch ( slapMode & SLAP_MODE ) {
		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, DETAIL1, 
				"init: %s initiation, initiated %s.\n",
				name, (mode & SLAP_MODE) == SLAP_TOOL_MODE ? 
				  "tool" : "server", 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"%s init: initiated %s.\n",	name,
				(mode & SLAP_MODE) == SLAP_TOOL_MODE ? "tool" : "server",
				0 );
#endif


			slap_name = name;
	
			(void) ldap_pvt_thread_initialize();

			ldap_pvt_thread_pool_init(&connection_pool, connection_pool_max, 0);

			ldap_pvt_thread_mutex_init( &entry2str_mutex );
			ldap_pvt_thread_mutex_init( &replog_mutex );
			ldap_pvt_thread_mutex_init( &num_ops_mutex );
			ldap_pvt_thread_mutex_init( &num_sent_mutex );

#ifdef SLAPD_MONITOR
			{
				int i;
				for ( i = 0; i < SLAP_OP_LAST; i++ ) {
					num_ops_initiated_[ i ] = 0;
					num_ops_completed_[ i ] = 0;
				}
			}
#endif

			ldap_pvt_thread_mutex_init( &gmtime_mutex );
#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
			ldap_pvt_thread_mutex_init( &passwd_mutex );
#endif

			rc = slap_sasl_init();

			if( rc == 0 ) {
				rc = backend_init( );
			}
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"init: %s init, undefined mode (%d).\n", name, mode, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s init: undefined mode (%d).\n", name, mode, 0 );
#endif

			rc = 1;
			break;
	}

	return rc;
}

int slap_startup( Backend *be )
{
	int rc;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, CRIT, "slap_startup: %s started\n", slap_name, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"%s startup: initiated.\n",
		slap_name, 0, 0 );
#endif


	rc = backend_startup( be );

	return rc;
}

int slap_shutdown( Backend *be )
{
	int rc;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, CRIT, 
		"slap_shutdown: %s shutdown initiated.\n", slap_name, 0, 0);
#else
	Debug( LDAP_DEBUG_TRACE,
		"%s shutdown: initiated\n",
		slap_name, 0, 0 );
#endif


	slap_sasl_destroy();

	/* let backends do whatever cleanup they need to do */
	rc = backend_shutdown( be ); 

	return rc;
}

int slap_destroy(void)
{
	int rc;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, INFO, 
		"slap_destroy: %s freeing system resources.\n", slap_name, 0, 0);
#else
	Debug( LDAP_DEBUG_TRACE,
		"%s shutdown: freeing system resources.\n",
		slap_name, 0, 0 );
#endif


	rc = backend_destroy();

	entry_destroy();

	ldap_pvt_thread_destroy();

	/* should destory the above mutex */
	return rc;
}

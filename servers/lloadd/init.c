/* init.c - initialize various things */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2020 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "lber_pvt.h"

#include "ldap_rq.h"

/*
 * read-only global variables or variables only written by the listener
 * thread (after they are initialized) - no need to protect them with a mutex.
 */
int slap_debug = 0;

#ifdef LDAP_DEBUG
int ldap_syslog = LDAP_DEBUG_STATS;
#else
int ldap_syslog;
#endif

#ifdef LOG_DEBUG
int ldap_syslog_level = LOG_DEBUG;
#endif

/*
 * global variables that need mutex protection
 */
ldap_pvt_thread_pool_t connection_pool;
int connection_pool_max = SLAP_MAX_WORKER_THREADS;
int connection_pool_queues = 1;
int slap_tool_thread_max = 1;

static const char *slap_name = NULL;
int slapMode = SLAP_UNDEFINED_MODE;

int
slap_init( int mode, const char *name )
{
    int rc = LDAP_SUCCESS;

    assert( mode );

    if ( slapMode != SLAP_UNDEFINED_MODE ) {
        /* Make sure we write something to stderr */
        slap_debug |= LDAP_DEBUG_NONE;
        Debug( LDAP_DEBUG_ANY, "%s init: "
                "init called twice (old=%d, new=%d)\n",
                name, slapMode, mode );

        return 1;
    }

    slapMode = mode;

    switch ( slapMode & SLAP_MODE ) {
        case SLAP_SERVER_MODE:
            Debug( LDAP_DEBUG_TRACE, "%s init: "
                    "initiated server.\n",
                    name );

            slap_name = name;

            ldap_pvt_thread_pool_init_q( &connection_pool, connection_pool_max,
                    0, connection_pool_queues );

            ldap_pvt_thread_mutex_init( &slapd_rq.rq_mutex );
            LDAP_STAILQ_INIT( &slapd_rq.task_list );
            LDAP_STAILQ_INIT( &slapd_rq.run_list );

            ldap_pvt_thread_mutex_init( &backend_mutex );

            break;

        default:
            slap_debug |= LDAP_DEBUG_NONE;
            Debug( LDAP_DEBUG_ANY, "%s init: "
                    "undefined mode (%d).\n",
                    name, mode );

            rc = 1;
            break;
    }

    return rc;
}

int
slap_destroy( void )
{
    int rc = LDAP_SUCCESS;

    Debug( LDAP_DEBUG_TRACE, "%s destroy: "
            "freeing system resources.\n",
            slap_name );

    ldap_pvt_thread_pool_free( &connection_pool );

    switch ( slapMode & SLAP_MODE ) {
        case SLAP_SERVER_MODE:
            break;

        default:
            Debug( LDAP_DEBUG_ANY, "slap_destroy(): "
                    "undefined mode (%d).\n",
                    slapMode );

            rc = 1;
            break;
    }

    ldap_pvt_thread_destroy();

    /* should destroy the above mutex */
    return rc;
}

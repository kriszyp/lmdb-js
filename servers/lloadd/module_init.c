/* module_init.c - module initialization functions */
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

#include "../servers/slapd/slap.h"

#include "lload.h"
#include "lber_pvt.h"

#include "ldap_rq.h"

int
lload_start_daemon()
{
    struct event_base *daemon_base = event_base_new();
    int rc = 0, i;
    if ( !daemon_base ) {
        Debug( LDAP_DEBUG_ANY, "lload_start_daemon: "
                "main event base allocation failed\n" );
        rc = 1;
        return rc;
    }

    rc = lloadd_daemon( daemon_base );
    return rc;
}

/* from init.c */
int
lload_conn_pool_init()
{
    int rc = 0;

    ldap_pvt_thread_mutex_init( &backend_mutex );
    ldap_pvt_thread_mutex_init( &clients_mutex );

    lload_exop_init();
    Debug( LDAP_DEBUG_TRACE, "lload_conn_pool_init: "
            "mutexes initialized.\n" );
    return rc;
}

void *
lload_module_start_daemon( void *ctx, void *arg )
{
    lload_start_daemon();
    return NULL;
}

int
init_module( int argc, char *argv[] )
{
    if ( slapMode & SLAP_TOOL_MODE ) {
        return 0;
    }
    if ( lload_libevent_init() ) {
        return -1;
    }
    global_host = ldap_pvt_get_fqdn( NULL );
#ifdef HAVE_TLS
    if ( ldap_create( &lload_tls_backend_ld ) ) {
        return -1;
    }
#endif /* HAVE_TLS */

    if ( lloadd_daemon_init( argv[1] ) != 0 ) {
        return -1;
    }
    lload_conn_pool_init();

    if ( lload_read_config( argv[0], NULL ) != 0 ) {
        return -1;
    }

    ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
    ldap_pvt_runqueue_insert( &slapd_rq, 0, lload_module_start_daemon, NULL,
            "lload_module_start_daemon", "lloadd" );
    ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );
    return 0;
}

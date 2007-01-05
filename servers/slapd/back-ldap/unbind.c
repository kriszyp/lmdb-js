/* unbind.c - ldap backend unbind function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2007 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Howard Chu.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_conn_destroy(
		Backend		*be,
		Connection	*conn
)
{
	ldapinfo_t	*li = (ldapinfo_t *) be->be_private;
	ldapconn_t	*lc = NULL, lc_curr;

	Debug( LDAP_DEBUG_TRACE,
		"=>ldap_back_conn_destroy: fetching conn %ld\n",
		conn->c_connid, 0, 0 );

	lc_curr.lc_conn = conn;
	
	ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
#if LDAP_BACK_PRINT_CONNTREE > 0
	ldap_back_print_conntree( li, ">>> ldap_back_conn_destroy" );
#endif /* LDAP_BACK_PRINT_CONNTREE */
	while ( ( lc = avl_delete( &li->li_conninfo.lai_tree, (caddr_t)&lc_curr, ldap_back_conn_cmp ) ) != NULL )
	{
		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_conn_destroy: destroying conn %ld (refcnt=%u)\n",
			LDAP_BACK_PCONN_ID( lc ), lc->lc_refcnt, 0 );

		assert( lc->lc_refcnt == 0 );

		/*
		 * Needs a test because the handler may be corrupted,
		 * and calling ldap_unbind on a corrupted header results
		 * in a segmentation fault
		 */
		ldap_back_conn_free( lc );
	}
#if LDAP_BACK_PRINT_CONNTREE > 0
	ldap_back_print_conntree( li, "<<< ldap_back_conn_destroy" );
#endif /* LDAP_BACK_PRINT_CONNTREE */
	ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );

	return 0;
}

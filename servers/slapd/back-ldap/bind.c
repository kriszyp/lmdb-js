/* bind.c - ldap backend bind function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* This is an altered version */
/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>


#define AVL_INTERNAL
#include "slap.h"
#include "back-ldap.h"

int
ldap_back_bind(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    const char		*dn,
    const char		*ndn,
    int			method,
    struct berval	*cred,
	char		**edn
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;

	char *mdn = NULL;
	int rc = 0;

	*edn = NULL;

	lc = ldap_back_getconn(li, conn, op);
	if ( !lc ) {
		return( -1 );
	}

	mdn = ldap_back_dn_massage( li, ch_strdup( dn ), 0 );
	if ( mdn == NULL ) {
		return -1;
	}

	if (ldap_bind_s(lc->ld, mdn, cred->bv_val, method) != LDAP_SUCCESS) {
		rc = ldap_back_op_result( lc, op );
	} else {
		lc->bound = 1;
	}
	
	free( mdn );
	
	return( rc );
}

/*
 * conn_cmp
 *
 * compares two struct ldapconn based on the value of the conn pointer;
 * used by avl stuff
 */
int
conn_cmp(
	const void *c1,
	const void *c2
	)
{
	struct ldapconn *lc1 = (struct ldapconn *)c1;
        struct ldapconn *lc2 = (struct ldapconn *)c2;
	
	return ( ( lc1->conn < lc2->conn ) ? -1 : ( ( lc1->conn > lc2-> conn ) ? 1 : 0 ) );
}

/*
 * conn_dup
 *
 * returns -1 in case a duplicate struct ldapconn has been inserted;
 * used by avl stuff
 */
int
conn_dup(
	void *c1,
	void *c2
	)
{
	struct ldapconn *lc1 = (struct ldapconn *)c1;
	struct ldapconn *lc2 = (struct ldapconn *)c2;

	return( ( lc1->conn == lc2->conn ) ? -1 : 0 );
}

static void ravl_print( Avlnode *root, int depth )
{
	int     i;
	
	if ( root == 0 )
		return;
	
	ravl_print( root->avl_right, depth+1 );
	
	for ( i = 0; i < depth; i++ )
		printf( "   " );

	printf( "c(%d) %d\n", ((struct ldapconn *) root->avl_data)->conn->c_connid, root->avl_bf );
	
	ravl_print( root->avl_left, depth+1 );
}

static void myprint( Avlnode *root )
{
	printf( "********\n" );
	
	if ( root == 0 )
		printf( "\tNULL\n" );

	else
		ravl_print( root, 0 );
	
	printf( "********\n" );
}

struct ldapconn *
ldap_back_getconn(struct ldapinfo *li, Connection *conn, Operation *op)
{
	struct ldapconn *lc, lc_curr;
	LDAP *ld;

	/* Searches for a ldapconn in the avl tree */
	lc_curr.conn = conn;
	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = (struct ldapconn *)avl_find( li->conntree, 
		(caddr_t)&lc_curr, conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if (!lc) {
		int vers = conn->c_protocol;
		int err = ldap_initialize(&ld, li->url);
		
		if (err != LDAP_SUCCESS) {
			err = ldap_back_map_result(err);
			send_ldap_result( conn, op, err,
				NULL, "ldap_init failed", NULL, NULL );
			return( NULL );
		}
		/* Set LDAP version. This will always succeed: If the client
		 * bound with a particular version, then so can we.
		 */
		ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &vers);

		lc = (struct ldapconn *)ch_malloc(sizeof(struct ldapconn));
		lc->conn = conn;
		lc->ld = ld;
		if ( lc->conn->c_cdn != NULL && lc->conn->c_cdn[0] != '\0' ) {
			lc->bound_dn = ldap_back_dn_massage( li,
				ch_strdup( lc->conn->c_cdn ), 0 );
		} else {
			lc->bound_dn = NULL;
		}
		lc->bound = 0;

		/* Inserts the newly created ldapconn in the avl tree */
		ldap_pvt_thread_mutex_lock( &li->conn_mutex );
		err = avl_insert( &li->conntree, (caddr_t)lc,
			conn_cmp, conn_dup );

#if 1
		myprint( li->conntree );
#endif
		
		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_getconn: conn %d inserted\n",
			lc->conn->c_connid, 0, 0 );
		
		/* Err could be -1 in case a duplicate ldapconn is inserted */
		if ( err != 0 ) {
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "internal server error", NULL, NULL );
			/* better destroy the ldapconn struct? */
			return( NULL );
		}
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_getconn: conn %d fetched\n",
			lc->conn->c_connid, 0, 0 );
	}
	
	return( lc );
}

/*
 * ldap_back_dobind
 *
 * Note: as the check for the value of lc->bound was already here, I removed
 * it from all the callers, and I made the function return the flag, so
 * it can be used to simplify the check.
 */
int
ldap_back_dobind(struct ldapconn *lc, Operation *op)
{
	if (lc->bound) {
		return( lc->bound );
	}

	if (ldap_bind_s(lc->ld, lc->bound_dn, NULL, LDAP_AUTH_SIMPLE) !=
		LDAP_SUCCESS) {
		ldap_back_op_result(lc, op);
		return( 0 );
	} /* else */
	return( lc->bound = 1 );
}

/* Map API errors to protocol errors... */

int
ldap_back_map_result(int err)
{
	switch(err)
	{
	case LDAP_SERVER_DOWN:
		return LDAP_UNAVAILABLE;
	case LDAP_LOCAL_ERROR:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_ENCODING_ERROR:
	case LDAP_DECODING_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_TIMEOUT:
		return LDAP_UNAVAILABLE;
	case LDAP_AUTH_UNKNOWN:
		return LDAP_AUTH_METHOD_NOT_SUPPORTED;
	case LDAP_FILTER_ERROR:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_USER_CANCELLED:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_PARAM_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_MEMORY:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_CONNECT_ERROR:
		return LDAP_UNAVAILABLE;
	case LDAP_NOT_SUPPORTED:
		return LDAP_UNWILLING_TO_PERFORM;
	case LDAP_CONTROL_NOT_FOUND:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_RESULTS_RETURNED:
		return LDAP_NO_SUCH_OBJECT;
	case LDAP_MORE_RESULTS_TO_RETURN:
		return LDAP_OTHER;
	case LDAP_CLIENT_LOOP:
	case LDAP_REFERRAL_LIMIT_EXCEEDED:
		return LDAP_LOOP_DETECT;
	default:
		if LDAP_API_ERROR(err)
			return LDAP_OTHER;
		else
			return err;
	}
}

int
ldap_back_op_result(struct ldapconn *lc, Operation *op)
{
	int err = LDAP_SUCCESS;
	char *msg = NULL;
	char *match = NULL;

	ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &err);
	ldap_get_option(lc->ld, LDAP_OPT_ERROR_STRING, &msg);
	ldap_get_option(lc->ld, LDAP_OPT_MATCHED_DN, &match);
	err = ldap_back_map_result(err);
	send_ldap_result( lc->conn, op, err, match, msg, NULL, NULL );
	/* better test the pointers before freeing? */
	if ( match ) free( match );
	if ( msg ) free( msg );
	return( (err==LDAP_SUCCESS) ? 0 : -1 );
}

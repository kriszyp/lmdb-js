/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  open.c
 */

#include "portable.h"

#include <stdio.h>
#include <limits.h>

#include <ac/stdlib.h>

#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

int ldap_open_defconn( LDAP *ld )
{
	if (( ld->ld_defconn = ldap_new_connection( ld, ld->ld_options.ldo_defludp, 1,1,NULL )) == NULL )
	{
		ld->ld_errno = LDAP_SERVER_DOWN;
		return -1;
	}

	++ld->ld_defconn->lconn_refcnt;	/* so it never gets closed/freed */

	return 0;
}

/*
 * ldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 * "host" may be a space-separated list of hosts or IP addresses
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_open( hostname, port );
 */

LDAP *
ldap_open( LDAP_CONST char *host, int port )
{
	int rc;
	LDAP		*ld;

	Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

	if (( ld = ldap_init( host, port )) == NULL ) {
		return( NULL );
	}

	rc = ldap_open_defconn( ld );

	if( rc < 0 ) {
		ldap_ld_free( ld, 0, NULL, NULL );
		return( NULL );
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_open successful, ld_host is %s\n",
		( ld->ld_host == NULL ) ? "(null)" : ld->ld_host, 0, 0 );

	return( ld );
}



int
ldap_create( LDAP **ldp )
{
	LDAP			*ld;
	struct ldapoptions	*gopts;

	*ldp = NULL;
	/* Get pointer to global option structure */
	if ( (gopts = LDAP_INT_GLOBAL_OPT()) == NULL) {
		return LDAP_NO_MEMORY;
	}

	/* Initialize the global options, if not already done. */
	if( gopts->ldo_valid != LDAP_INITIALIZED ) {
		ldap_int_initialize(gopts, NULL);
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_init\n", 0, 0, 0 );

#ifdef HAVE_WINSOCK2
{	WORD wVersionRequested;
	WSADATA wsaData;
 
	wVersionRequested = MAKEWORD( 2, 0 );
	if ( WSAStartup( wVersionRequested, &wsaData ) != 0 ) {
		/* Tell the user that we couldn't find a usable */
		/* WinSock DLL.                                  */
		return LDAP_LOCAL_ERROR;
	}
 
	/* Confirm that the WinSock DLL supports 2.0.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.0 in addition to 2.0, it will still return */
	/* 2.0 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 0 )
	{
	    /* Tell the user that we couldn't find a usable */
	    /* WinSock DLL.                                  */
	    WSACleanup( );
	    return LDAP_LOCAL_ERROR; 
	}
}	/* The WinSock DLL is acceptable. Proceed. */

#elif HAVE_WINSOCK
{	WSADATA wsaData;
	if ( WSAStartup( 0x0101, &wsaData ) != 0 ) {
	    return LDAP_LOCAL_ERROR;
	}
}
#endif

	if ( (ld = (LDAP *) LDAP_CALLOC( 1, sizeof(LDAP) )) == NULL ) {
	    WSACleanup( );
		return( LDAP_NO_MEMORY );
	}
   
	/* copy the global options */
	memcpy(&ld->ld_options, gopts, sizeof(ld->ld_options));

	ld->ld_valid = LDAP_VALID_SESSION;

	/* but not pointers to malloc'ed items */
	ld->ld_options.ldo_defludp = NULL;
	ld->ld_options.ldo_sctrls = NULL;
	ld->ld_options.ldo_cctrls = NULL;

	ld->ld_options.ldo_defludp = ldap_url_duplist(gopts->ldo_defludp);

	if ( ld->ld_options.ldo_defludp == NULL ) {
		LDAP_FREE( (char*)ld );
	    WSACleanup( );
		return LDAP_NO_MEMORY;
	}

	if (( ld->ld_selectinfo = ldap_new_select_info()) == NULL ) {
		ldap_free_urllist( ld->ld_options.ldo_defludp );
		LDAP_FREE( (char*) ld );
	    WSACleanup( );
		return LDAP_NO_MEMORY;
	}

	ld->ld_lberoptions = LBER_USE_DER;

	ld->ld_sb = ber_sockbuf_alloc( );
	if ( ld->ld_sb == NULL ) {
		ldap_free_urllist( ld->ld_options.ldo_defludp );
		LDAP_FREE( (char*) ld );
		WSACleanup( );
		return LDAP_NO_MEMORY;
	}

	*ldp = ld;
	return LDAP_SUCCESS;
}

/*
 * ldap_init - initialize the LDAP library.  A magic cookie to be used for
 * future communication is returned on success, NULL on failure.
 * "host" may be a space-separated list of hosts or IP addresses
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_open( host, port );
 */
LDAP *
ldap_init( LDAP_CONST char *defhost, int defport )
{
	LDAP *ld;
	int rc;

	rc = ldap_create(&ld);
	if ( rc != LDAP_SUCCESS )
		return NULL;

	if (defport != 0)
		ld->ld_options.ldo_defport = defport;

	if (defhost != NULL) {
		rc = ldap_set_option(ld, LDAP_OPT_HOST_NAME, defhost);
		if ( rc != LDAP_SUCCESS ) {
			ldap_ld_free(ld, 1, NULL, NULL);
			return NULL;
		}
	}

	return( ld );
}


int
ldap_initialize( LDAP **ldp, LDAP_CONST char *url )
{
	int rc;
	LDAP *ld;

	*ldp = NULL;
	rc = ldap_create(&ld);
	if ( rc != LDAP_SUCCESS )
		return rc;

	if (url != NULL) {
		rc = ldap_set_option(ld, LDAP_OPT_URI, url);
		if ( rc != LDAP_SUCCESS ) {
			ldap_ld_free(ld, 1, NULL, NULL);
			return rc;
		}
	}

	*ldp = ld;
	return LDAP_SUCCESS;
}

int
ldap_start_tls ( LDAP *ld,
				LDAPControl **serverctrls,
				LDAPControl **clientctrls )
{
#ifdef HAVE_TLS
	LDAPConn *lc;
	int rc;
	char *rspoid = NULL;
	struct berval *rspdata = NULL;

	if (ld->ld_conns == NULL) {
		rc = ldap_open_defconn( ld );
		if (rc != LDAP_SUCCESS)
			return(rc);
	}

	for (lc = ld->ld_conns; lc != NULL; lc = lc->lconn_next) {
		if (ldap_pvt_tls_inplace(lc->lconn_sb) != 0)
			return LDAP_OPERATIONS_ERROR;
		rc = ldap_extended_operation_s(ld, LDAP_EXOP_START_TLS,
							NULL, serverctrls, clientctrls, &rspoid, &rspdata);
		if (rc != LDAP_SUCCESS)
			return rc;
		if (rspoid != NULL)
			LDAP_FREE(rspoid);
		if (rspdata != NULL)
			ber_bvfree(rspdata);
		rc = ldap_pvt_tls_start( ld, lc->lconn_sb, ld->ld_options.ldo_tls_ctx );
		if (rc != LDAP_SUCCESS)
			return rc;
	}
	return LDAP_SUCCESS;
#else
	return LDAP_NOT_SUPPORTED;
#endif
}

int
open_ldap_connection( LDAP *ld, Sockbuf *sb, LDAPURLDesc *srv,
	char **krbinstancep, int async )
{
	int rc = -1;
	int port;
	long addr;

	Debug( LDAP_DEBUG_TRACE, "open_ldap_connection\n", 0, 0, 0 );

	port = srv->lud_port;
	if (port == 0)
		port = ld->ld_options.ldo_defport;
	port = htons( (short) port );

	addr = 0;
	if ( srv->lud_host == NULL || *srv->lud_host == 0 )
		addr = htonl( INADDR_LOOPBACK );

	switch ( ldap_pvt_url_scheme2proto( srv->lud_scheme ) ) {
		case LDAP_PROTO_TCP:
			rc = ldap_connect_to_host( ld, sb, srv->lud_host,
				addr, port, async );
			if ( rc == -1 )
				return rc;
			ber_sockbuf_add_io( sb, &ber_sockbuf_io_tcp,
				LBER_SBIOD_LEVEL_PROVIDER, NULL );
			break;
		case LDAP_PROTO_UDP:
			rc = ldap_connect_to_host( ld, sb, srv->lud_host,
				addr, port, async );
			if ( rc == -1 )
				return rc;
			ber_sockbuf_add_io( sb, &ber_sockbuf_io_udp,
				LBER_SBIOD_LEVEL_PROVIDER, NULL );
			break;
		case LDAP_PROTO_IPC:
#ifdef LDAP_PF_UNIX
			/* only IPC mechanism supported is PF_UNIX */
			rc = ldap_connect_to_path( ld, sb, srv->lud_host,
				async );
			if ( rc == -1 )
				return rc;
			ber_sockbuf_add_io( sb, &ber_sockbuf_io_fd,
				LBER_SBIOD_LEVEL_PROVIDER, NULL );
			break;
#endif /* LDAP_PF_UNIX */
		default:
			return -1;
			break;
	}

	ber_sockbuf_add_io( sb, &ber_sockbuf_io_readahead,
		LBER_SBIOD_LEVEL_PROVIDER, NULL );
#ifdef LDAP_DEBUG
	ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug, INT_MAX, NULL );
#endif

#ifdef HAVE_TLS
	if (ld->ld_options.ldo_tls_mode == LDAP_OPT_X_TLS_HARD ||
		strcmp( srv->lud_scheme, "ldaps" ) == 0 )
	{
		rc = ldap_pvt_tls_start( ld, sb, ld->ld_options.ldo_tls_ctx );
		if (rc != LDAP_SUCCESS)
			return rc;
	}
#endif

	if ( krbinstancep != NULL ) {
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		char *c;
		if (( *krbinstancep = ldap_host_connected_to( sb )) != NULL &&
		    ( c = strchr( *krbinstancep, '.' )) != NULL ) {
			*c = '\0';
		}
#else /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND */
		*krbinstancep = NULL;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND */
	}

	return( 0 );
}

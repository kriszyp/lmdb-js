/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ac/stdlib.h>

#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

int ldap_open_defconn( LDAP *ld )
{
	LDAPServer	*srv;

	if (( srv = (LDAPServer *)LDAP_CALLOC( 1, sizeof( LDAPServer ))) ==
	    NULL || ( ld->ld_defhost != NULL && ( srv->lsrv_host =
	    LDAP_STRDUP( ld->ld_defhost )) == NULL ))
	{
		if( srv != NULL ) LDAP_FREE( (char*) srv );
		ld->ld_errno = LDAP_NO_MEMORY;
		return -1;
	}

	srv->lsrv_port = ld->ld_defport;

	if (( ld->ld_defconn = ldap_new_connection( ld, &srv, 1,1,0 )) == NULL )
	{
		if ( ld->ld_defhost != NULL ) LDAP_FREE( srv->lsrv_host );
		LDAP_FREE( (char *)srv );
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
	LDAP			*ld;

	if( ldap_int_global_options.ldo_valid != LDAP_INITIALIZED ) {
		ldap_int_initialize();
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_init\n", 0, 0, 0 );

#ifdef HAVE_WINSOCK2
{	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD( 2, 0 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		/* Tell the user that we couldn't find a usable */
		/* WinSock DLL.                                  */
		return NULL;
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
	    return NULL; 
	}
}	/* The WinSock DLL is acceptable. Proceed. */

#elif HAVE_WINSOCK
{	WSADATA wsaData;
	if ( WSAStartup( 0x0101, &wsaData ) != 0 ) {
	    return( NULL );
	}
}
#endif

	if ( (ld = (LDAP *) LDAP_CALLOC( 1, sizeof(LDAP) )) == NULL ) {
	    WSACleanup( );
		return( NULL );
	}
   
	/* copy the global options */
	memcpy(&ld->ld_options, &ldap_int_global_options,
		sizeof(ld->ld_options));

	ld->ld_valid = LDAP_VALID_SESSION;

	/* but not pointers to malloc'ed items */
	ld->ld_options.ldo_defbase = NULL;
	ld->ld_options.ldo_defhost = NULL;
	ld->ld_options.ldo_sctrls = NULL;
	ld->ld_options.ldo_cctrls = NULL;

	if ( defhost != NULL ) {
		ld->ld_options.ldo_defhost = LDAP_STRDUP( defhost );
	} else {
		ld->ld_options.ldo_defhost = LDAP_STRDUP(
			ldap_int_global_options.ldo_defhost);
	}

	if ( ld->ld_options.ldo_defhost == NULL ) {
		LDAP_FREE( (char*)ld );
	    WSACleanup( );
		return( NULL );
	}

	if ( ldap_int_global_options.ldo_defbase != NULL ) {
		ld->ld_options.ldo_defbase = LDAP_STRDUP(
			ldap_int_global_options.ldo_defbase);
	}

	if (( ld->ld_selectinfo = ldap_new_select_info()) == NULL ) {
		LDAP_FREE( (char*) ld->ld_options.ldo_defhost );
		if ( ld->ld_options.ldo_defbase == NULL ) {
			LDAP_FREE( (char*) ld->ld_options.ldo_defbase );
		}
		LDAP_FREE( (char*) ld );
	    WSACleanup( );
		return( NULL );
	}

	if(defport != 0) {
		ld->ld_defport = defport;
	}

	ld->ld_lberoptions = LBER_USE_DER;

#if defined( STR_TRANSLATION ) && defined( LDAP_DEFAULT_CHARSET )
	ld->ld_lberoptions |= LBER_TRANSLATE_STRINGS;
#if LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET
	ldap_set_string_translators( ld, ldap_8859_to_t61, ldap_t61_to_8859 );
#endif /* LDAP_CHARSET_8859 == LDAP_DEFAULT_CHARSET */
#endif /* STR_TRANSLATION && LDAP_DEFAULT_CHARSET */

	/* we'll assume we're talking version 2 for now */
	ld->ld_version = LDAP_VERSION2;

	ber_pvt_sb_init( &(ld->ld_sb) );

	return( ld );
}


int
open_ldap_connection( LDAP *ld, Sockbuf *sb, const char *host, int defport,
	char **krbinstancep, int async )
{
	int 			rc = -1;
	int				port;
	const char		*p, *q;
	char			*r, *curhost, hostname[ 2*MAXHOSTNAMELEN ];

	Debug( LDAP_DEBUG_TRACE, "open_ldap_connection\n", 0, 0, 0 );

	defport = htons( (short) defport );

	if ( host != NULL ) {
		for ( p = host; p != NULL && *p != '\0'; p = q ) {
			if (( q = strchr( p, ' ' )) != NULL ) {
				strncpy( hostname, p, q - p );
				hostname[ q - p ] = '\0';
				curhost = hostname;
				while ( *q == ' ' ) {
				    ++q;
				}
			} else {
				curhost = (char *) p;	/* avoid copy if possible */
				q = NULL;
			}

			if (( r = strchr( curhost, ':' )) != NULL ) {
			    if ( curhost != hostname ) {
				strcpy( hostname, curhost );	/* now copy */
				r = hostname + ( r - curhost );
				curhost = hostname;
			    }
			    *r++ = '\0';
			    port = htons( (short) atoi( r ) );
			} else {
			    port = defport;   
			}

			if (( rc = ldap_connect_to_host( ld, sb, curhost, 0L,
			    port, async )) != -1 ) {
				break;
			}
		}
	} else {
		rc = ldap_connect_to_host( ld, sb, 0, htonl( INADDR_LOOPBACK ),
		    defport, async );
	}

	if ( rc == -1 ) {
		return( rc );
	}
   
   	ber_pvt_sb_set_io( sb, &ber_pvt_sb_io_tcp, NULL );

#ifdef HAVE_TLS
   	if ( ld->ld_options.ldo_tls_mode == LDAP_OPT_X_TLS_HARD ) {
		/*
		 * Fortunately, the lib uses blocking io...
		 */
		if ( ldap_pvt_tls_connect( sb, ld->ld_options.ldo_tls_ctx ) < 
		     0 ) {
			return -1;
		}
		/* FIXME: hostname of server must be compared with name in
		 * certificate....
		 */
	}
#endif
	if ( krbinstancep != NULL ) {
#ifdef HAVE_KERBEROS
		char *c;
		if (( *krbinstancep = ldap_host_connected_to( sb )) != NULL &&
		    ( c = strchr( *krbinstancep, '.' )) != NULL ) {
			*c = '\0';
		}
#else /* HAVE_KERBEROS */
		krbinstancep = NULL;
#endif /* HAVE_KERBEROS */
	}

	return( 0 );
}

/*
 *  Copyright (c) 1992, 1994 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  kerberos.c - for the windows environment
 */

#include <msdos.h>
#include "lber.h"
#include "ldap.h"

#ifdef KERBEROS
#ifdef WINSOCK
#include <winsock.h>
#endif
#include <stdio.h>

#ifdef AUTHMAN
#include <authlib.h>

/*
 * get_kerberosv4_credentials - obtain kerberos v4 credentials for ldap.
 * this includes krbtgt, and any service tickets
 */

/* ARGSUSED */
char *
get_kerberosv4_credentials( LDAP *ld, char *who, char *service, int *len )
{
    static short    authman_refnum = 0;
    static          char ticket[ MAX_KTXT_LEN ];
    short           version, ticketlen, err;
    AUTH_PTR        ticketStorage = ticket;
    AUTH_SHORT_PTR  pTicketLen = &ticketlen;
    AUTH_STR_PTR    pName = service;
    AUTH_STR_PTR    pInstance;
    HINSTANCE       instAuthLibDLL = NULL;
    pfn_openAuthMan fp_openAuthMan = NULL;
    pfn_closeAuthMan fp_closeAuthMan = NULL;
    pfn_getV4Ticket fp_getV4Ticket = NULL;


#ifdef LDAP_REFERRALS
	pInstance = ld->ld_defconn->lconn_krbinstance;
#else /* LDAP_REFERRALS */
	pInstance = ld->ld_host;
#endif /* LDAP_REFERRALS */

    if ( !pInstance ) {	// if we don't know name of service host, no chance for service tickets
        ld->ld_errno = LDAP_LOCAL_ERROR;
        WSASetLastError(WSANO_ADDRESS);
    	return( NULL );
    }
    
    if ( !instAuthLibDLL )
    {
        unsigned int prevMode = SetErrorMode( SEM_NOOPENFILEERRORBOX ); // don't whine at user if you can't find it
        instAuthLibDLL = LoadLibrary("AuthLib.DLL");
        SetErrorMode( prevMode );

        if ( instAuthLibDLL < HINSTANCE_ERROR ) // can't find authlib
        {
            ld->ld_errno = LDAP_AUTH_UNKNOWN; 
            return( NULL );
        }
        
        fp_openAuthMan = (pfn_openAuthMan)GetProcAddress( instAuthLibDLL, "openAuthMan" );
        fp_getV4Ticket = (pfn_getV4Ticket)GetProcAddress( instAuthLibDLL, "getV4Ticket" );
        fp_closeAuthMan = (pfn_closeAuthMan)GetProcAddress( instAuthLibDLL, "closeAuthMan" );

        // verify that we found all the routines we need
        if (!(fp_closeAuthMan && fp_getV4Ticket && fp_openAuthMan))
        {
	        FreeLibrary( instAuthLibDLL ); // free authlib.dll so it gets unloaded
    	    instAuthLibDLL = NULL;
            ld->ld_errno = LDAP_AUTH_UNKNOWN; 
            return( NULL );
        }
        
    }

    /*
     * make sure RJC's Authentication Manager version isn't > 4.0
     */
     if ( authman_refnum == 0 && (( err = (fp_openAuthMan)( &authman_refnum, &version )) != AUTH_NO_ERROR || AUTH_VERSION_CODE > version )) {
        ld->ld_errno = LDAP_AUTH_UNKNOWN; 
        if ( AUTH_VERSION_CODE > version )
        {
            ld->ld_errno = LDAP_INAPPROPRIATE_AUTH; // version too old
        }
        (fp_closeAuthMan)( authman_refnum );
        authman_refnum = NULL;
        FreeLibrary( instAuthLibDLL ); // free authlib.dll so it gets unloaded
	    instAuthLibDLL = NULL;
        return( NULL );
    }
    
    if (( err = (fp_getV4Ticket)( authman_refnum, ticketStorage, pTicketLen, pName, pInstance,
            NULL, INFINITE_LIFETIME, 1 )) != AUTH_NO_ERROR ) {
        
        ld->ld_errno = AUTH_USER_CANCELED == err ? LDAP_USER_CANCELLED : LDAP_INVALID_CREDENTIALS;
        (fp_closeAuthMan)( authman_refnum );
        authman_refnum = NULL;
        FreeLibrary( instAuthLibDLL ); // free authlib.dll so it gets unloaded
	    instAuthLibDLL = NULL;
        return( NULL );
    }

    *len = ticketlen;
    (fp_closeAuthMan)( authman_refnum ); // open pukes if you call twice with no close in between
    authman_refnum = NULL;
    FreeLibrary( instAuthLibDLL ); // free authlib.dll so it gets unloaded
    instAuthLibDLL = NULL;
    return( (char *)ticket );
}

#endif /* AUTHMAN */
#endif /* KERBEROS */


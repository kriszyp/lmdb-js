/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * Portions Copyright 2003 Mark Benson.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *     Mark Benson
 */

/*
 * ldap_op.c - routines to perform LDAP operations
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include "lutil_ldap.h"
#include "slurp.h"

/* Forward references */
static struct berval **make_singlevalued_berval LDAP_P(( char	*, int ));
static int op_ldap_add LDAP_P(( Ri *, Re *, char **, int * ));
static int op_ldap_modify LDAP_P(( Ri *, Re *, char **, int * ));
static int op_ldap_delete LDAP_P(( Ri *, Re *, char **, int * ));
static int op_ldap_modrdn LDAP_P(( Ri *, Re *, char **, int * ));
static LDAPMod *alloc_ldapmod LDAP_P(( void ));
static void free_ldapmod LDAP_P(( LDAPMod * ));
static void free_ldmarr LDAP_P(( LDAPMod ** ));
static int getmodtype LDAP_P(( char * ));
#ifdef SLAPD_UNUSED
static void dump_ldm_array LDAP_P(( LDAPMod ** ));
#endif
static int do_bind LDAP_P(( Ri *, int * ));
static int do_unbind LDAP_P(( Ri * ));


/*
 * Determine the type of ldap operation being performed and call the
 * appropriate routine.
 * - If successful, returns DO_LDAP_OK
 * - If a retryable error occurs, ERR_DO_LDAP_RETRYABLE is returned.
 *   The caller should wait a while and retry the operation.
 * - If a fatal error occurs, ERR_DO_LDAP_FATAL is returned.  The caller
 *   should reject the operation and continue with the next replication
 *   entry.
 */
int
do_ldap(
	Ri		*ri,
	Re		*re,
	char	**errmsg,
	int	*errfree
)
{
	int	retry = 2;
	*errmsg = NULL;
	*errfree = 0;

	do {
		int lderr;
		if ( ri->ri_ldp == NULL ) {
			lderr = do_bind( ri, &lderr );

			if ( lderr != BIND_OK ) {
				return DO_LDAP_ERR_RETRYABLE;
			}
		}

		switch ( re->re_changetype ) {
		case T_ADDCT:
			lderr = op_ldap_add( ri, re, errmsg, errfree );
			if ( lderr != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"Error: ldap_add_s failed adding DN \"%s\": %s\n",
					re->re_dn, *errmsg && (*errmsg)[0] ?
					*errmsg : ldap_err2string( lderr ), 0 );
			}
			break;

		case T_MODIFYCT:
			lderr = op_ldap_modify( ri, re, errmsg, errfree );
			if ( lderr != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"Error: ldap_modify_s failed modifying DN \"%s\": %s\n",
					re->re_dn, *errmsg && (*errmsg)[0] ?
					*errmsg : ldap_err2string( lderr ), 0 );
			}
			break;

		case T_DELETECT:
			lderr = op_ldap_delete( ri, re, errmsg, errfree );
			if ( lderr != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"Error: ldap_delete_s failed deleting DN \"%s\": %s\n",
					re->re_dn, *errmsg && (*errmsg)[0] ?
					*errmsg : ldap_err2string( lderr ), 0 );
			}
			break;

		case T_MODRDNCT:
			lderr = op_ldap_modrdn( ri, re, errmsg, errfree );
			if ( lderr != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"Error: ldap_modrdn_s failed modifying DN \"%s\": %s\n",
					re->re_dn, *errmsg && (*errmsg)[0] ?
					*errmsg : ldap_err2string( lderr ), 0 );
			}
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
				"Error: do_ldap: bad op \"%d\", DN \"%s\"\n",
				re->re_changetype, re->re_dn, 0 );
			return DO_LDAP_ERR_FATAL;
		}

		/*
		 * Analyze return code. If ok, just return. If LDAP_SERVER_DOWN,
		 * we may have been idle long enough that the remote slapd timed
		 * us out. Rebind and try again.
		 */
		switch( lderr ) {
		case LDAP_SUCCESS:
			return DO_LDAP_OK;
	
		default:
			return DO_LDAP_ERR_FATAL;

		case LDAP_SERVER_DOWN: /* server went down */
			(void) do_unbind( ri );
 			retry--;
		}
	} while ( retry > 0 );

	return DO_LDAP_ERR_RETRYABLE;
}



/*
 * Perform an ldap add operation.
 */
static int
op_ldap_add(
    Ri		*ri,
    Re		*re,
    char	**errmsg,
    int		*errfree
)
{
    Mi		*mi;
    int		nattrs, rc = 0, i;
    LDAPMod	*ldm, **ldmarr;
    int		lderr = 0;

    nattrs = i = 0;
    ldmarr = NULL;

    /*
     * Construct a null-terminated array of LDAPMod structs.
     */
    mi = re->re_mods;
    while ( mi[ i ].mi_type != NULL ) {
	ldm = alloc_ldapmod();
	ldmarr = ( LDAPMod ** ) ch_realloc( ldmarr,
		( nattrs + 2 ) * sizeof( LDAPMod * ));
	ldmarr[ nattrs ] = ldm;
	ldm->mod_op = LDAP_MOD_BVALUES;
	ldm->mod_type = mi[ i ].mi_type;
	ldm->mod_bvalues =
		make_singlevalued_berval( mi[ i ].mi_val, mi[ i ].mi_len );
	i++;
	nattrs++;
    }

    if ( ldmarr != NULL ) {
	ldmarr[ nattrs ] = NULL;

	/* Perform the operation */
	Debug( LDAP_DEBUG_ARGS, "replica %s:%d - add dn \"%s\"\n",
		ri->ri_hostname, ri->ri_port, re->re_dn );
	rc = ldap_add_s( ri->ri_ldp, re->re_dn, ldmarr );

	ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_NUMBER, &lderr);
	ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_STRING, errmsg);
	*errfree = 1;

    } else {
	*errmsg = "No modifications to do";
	Debug( LDAP_DEBUG_ANY,
	       "Error: op_ldap_add: no mods to do (%s)!\n", re->re_dn, 0, 0 );
    }
    free_ldmarr( ldmarr );
    return( lderr ); 
}




/*
 * Perform an ldap modify operation.
 */
#define	AWAITING_OP -1
static int
op_ldap_modify(
    Ri		*ri,
    Re		*re,
    char	**errmsg,
    int		*errfree
)
{
    Mi		*mi;
    int		state;	/* This code is a simple-minded state machine */
    int		nvals;	/* Number of values we're modifying */
    int		nops;	/* Number of LDAPMod structs in ldmarr */
    LDAPMod	*ldm = NULL, **ldmarr;
    int		i, len;
    char	*type, *value;
    int		rc = 0;

    state = AWAITING_OP;
    nvals = 0;
    nops = 0;
    ldmarr = NULL;

    if ( re->re_mods == NULL ) {
	*errmsg = "No arguments given";
	Debug( LDAP_DEBUG_ANY, "Error: op_ldap_modify: no arguments\n",
		0, 0, 0 );
	    return -1;
    }

    /*
     * Construct a null-terminated array of LDAPMod structs.
     */
    for ( mi = re->re_mods, i = 0; mi[ i ].mi_type != NULL; i++ ) {
	type = mi[ i ].mi_type;
	value = mi[ i ].mi_val;
	len = mi[ i ].mi_len;
	switch ( getmodtype( type )) {
	case T_MODSEP:
	    state = T_MODSEP; /* Got a separator line "-\n" */
	    continue;
	case T_MODOPADD:
	    state = T_MODOPADD;
	    ldmarr = ( LDAPMod ** )
		    ch_realloc(ldmarr, (( nops + 2 ) * ( sizeof( LDAPMod * ))));
	    ldmarr[ nops ] = ldm = alloc_ldapmod();
	    ldm->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
	    ldm->mod_type = value;
	    nvals = 0;
	    nops++;
	    break;
	case T_MODOPREPLACE:
	    state = T_MODOPREPLACE;
	    ldmarr = ( LDAPMod ** )
		    ch_realloc(ldmarr, (( nops + 2 ) * ( sizeof( LDAPMod * ))));
	    ldmarr[ nops ] = ldm = alloc_ldapmod();
	    ldm->mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
	    ldm->mod_type = value;
	    nvals = 0;
	    nops++;
	    break;
	case T_MODOPDELETE:
	    state = T_MODOPDELETE;
	    ldmarr = ( LDAPMod ** )
		    ch_realloc(ldmarr, (( nops + 2 ) * ( sizeof( LDAPMod * ))));
	    ldmarr[ nops ] = ldm = alloc_ldapmod();
	    ldm->mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
	    ldm->mod_type = value;
	    nvals = 0;
	    nops++;
	    break;
	case T_MODOPINCREMENT:
	    state = T_MODOPINCREMENT;
	    ldmarr = ( LDAPMod ** )
		    ch_realloc(ldmarr, (( nops + 2 ) * ( sizeof( LDAPMod * ))));
	    ldmarr[ nops ] = ldm = alloc_ldapmod();
	    ldm->mod_op = LDAP_MOD_INCREMENT | LDAP_MOD_BVALUES;
	    ldm->mod_type = value;
	    nvals = 0;
	    nops++;
	    break;
	default:
	    if ( state == AWAITING_OP ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: op_ldap_modify: unknown mod type \"%s\"\n",
			type, 0, 0 );
		continue;
	    }

	    assert( ldm != NULL );

	    /*
	     * We should have an attribute: value pair here.
	     * Construct the mod_bvalues part of the ldapmod struct.
	     */
	    if ( strcasecmp( type, ldm->mod_type )) {
		Debug( LDAP_DEBUG_ANY,
			"Error: malformed modify op, %s: %s (expecting %s:)\n",
			type, value, ldm->mod_type );
		continue;
	    }
	    ldm->mod_bvalues = ( struct berval ** )
		    ch_realloc( ldm->mod_bvalues,
		    ( nvals + 2 ) * sizeof( struct berval * ));
	    ldm->mod_bvalues[ nvals + 1 ] = NULL;
	    ldm->mod_bvalues[ nvals ] = ( struct berval * )
		    ch_malloc( sizeof( struct berval ));
	    ldm->mod_bvalues[ nvals ]->bv_val = value;
	    ldm->mod_bvalues[ nvals ]->bv_len = len;
	    nvals++;
	}
    }
    ldmarr[ nops ] = NULL;

    if ( nops > 0 ) {
	/* Actually perform the LDAP operation */
	Debug( LDAP_DEBUG_ARGS, "replica %s:%d - modify dn \"%s\"\n",
		ri->ri_hostname, ri->ri_port, re->re_dn );
	rc = ldap_modify_s( ri->ri_ldp, re->re_dn, ldmarr );
	ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_STRING, errmsg);
	*errfree = 1;
    }
    free_ldmarr( ldmarr );
    return( rc );
}




/*
 * Perform an ldap delete operation.
 */
static int
op_ldap_delete(
    Ri		*ri,
    Re		*re,
    char	**errmsg,
    int		*errfree
)
{
    int		rc;

    Debug( LDAP_DEBUG_ARGS, "replica %s:%d - delete dn \"%s\"\n",
	    ri->ri_hostname, ri->ri_port, re->re_dn );
    rc = ldap_delete_s( ri->ri_ldp, re->re_dn );
    ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_STRING, errmsg);
    *errfree = 1;

    return( rc );
}




/*
 * Perform an ldap modrdn operation.
 */
#define	GOT_NEWRDN		0x1
#define	GOT_DELOLDRDN	0x2
#define GOT_NEWSUP		0x4

#define GOT_MODDN_REQ	(GOT_NEWRDN|GOT_DELOLDRDN)
#define	GOT_ALL_MODDN(f)	(((f) & GOT_MODDN_REQ) == GOT_MODDN_REQ)
static int
op_ldap_modrdn(
    Ri		*ri,
    Re		*re,
    char	**errmsg,
    int		*errfree
)
{
    int		rc = 0;
    Mi		*mi;
    int		i;
	int		lderr = 0;
    int		state = 0;
    int		drdnflag = -1;
    char	*newrdn = NULL;
	char	*newsup = NULL;

    if ( re->re_mods == NULL ) {
	*errmsg = "No arguments given";
	Debug( LDAP_DEBUG_ANY, "Error: op_ldap_modrdn: no arguments\n",
		0, 0, 0 );
	    return -1;
    }

    /*
     * Get the arguments: should see newrdn: and deleteoldrdn: args.
     */
    for ( mi = re->re_mods, i = 0; mi[ i ].mi_type != NULL; i++ ) {
	if ( !strcmp( mi[ i ].mi_type, T_NEWRDNSTR )) {
		if( state & GOT_NEWRDN ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: op_ldap_modrdn: multiple newrdn arg \"%s\"\n",
			mi[ i ].mi_val, 0, 0 );
		*errmsg = "Multiple newrdn argument";
		return -1;
		}

	    newrdn = mi[ i ].mi_val;
	    state |= GOT_NEWRDN;

	} else if ( !strcmp( mi[ i ].mi_type, T_DELOLDRDNSTR )) {
		if( state & GOT_DELOLDRDN ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: op_ldap_modrdn: multiple deleteoldrdn arg \"%s\"\n",
			mi[ i ].mi_val, 0, 0 );
		*errmsg = "Multiple newrdn argument";
		return -1;
		}

	    state |= GOT_DELOLDRDN;
	    if ( !strcmp( mi[ i ].mi_val, "0" )) {
		drdnflag = 0;
	    } else if ( !strcmp( mi[ i ].mi_val, "1" )) {
		drdnflag = 1;
	    } else {
		Debug( LDAP_DEBUG_ANY,
			"Error: op_ldap_modrdn: bad deleteoldrdn arg \"%s\"\n",
			mi[ i ].mi_val, 0, 0 );
		*errmsg = "Incorrect argument to deleteoldrdn";
		return -1;
	    }

	} else if ( !strcmp( mi[ i ].mi_type, T_NEWSUPSTR )) {
		if( state & GOT_NEWSUP ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: op_ldap_modrdn: multiple newsuperior arg \"%s\"\n",
			mi[ i ].mi_val, 0, 0 );
		*errmsg = "Multiple newsuperior argument";
		return -1;
		}

		newsup = mi[ i ].mi_val;
	    state |= GOT_NEWSUP;

	} else {
	    Debug( LDAP_DEBUG_ANY, "Error: op_ldap_modrdn: bad type \"%s\"\n",
		    mi[ i ].mi_type, 0, 0 );
	    *errmsg = "Bad value in replication log entry";
	    return -1;
	}
    }

    /*
     * Punt if we don't have all the args.
     */
    if ( !GOT_ALL_MODDN(state) ) {
	Debug( LDAP_DEBUG_ANY, "Error: op_ldap_modrdn: missing arguments\n",
		0, 0, 0 );
	*errmsg = "Missing argument: requires \"newrdn\" and \"deleteoldrdn\"";
	return -1;
    }

#ifdef LDAP_DEBUG
    if ( ldap_debug & LDAP_DEBUG_ARGS ) {
	char buf[ 256 ];
	char *buf2;
	int buf2len = strlen( re->re_dn ) + strlen( mi->mi_val ) + 11;

	snprintf( buf, sizeof(buf), "%s:%d", ri->ri_hostname, ri->ri_port );

	buf2 = (char *) ch_malloc( buf2len );
	snprintf( buf2, buf2len, "(\"%s\" -> \"%s\")", re->re_dn, mi->mi_val );

	Debug( LDAP_DEBUG_ARGS,
		"replica %s - modify rdn %s (flag: %d)\n",
		buf, buf2, drdnflag );
	free( buf2 );
    }
#endif /* LDAP_DEBUG */

    assert( newrdn != NULL );

    /* Do the modrdn */
    rc = ldap_rename2_s( ri->ri_ldp, re->re_dn, newrdn, newsup, drdnflag );

	ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_NUMBER, &lderr);
	ldap_get_option( ri->ri_ldp, LDAP_OPT_ERROR_STRING, errmsg);
	*errfree = 1;
    return( lderr );
}



/*
 * Allocate and initialize an ldapmod struct.
 */
static LDAPMod *
alloc_ldapmod( void )
{
    LDAPMod	*ldm;

    ldm = ( struct ldapmod * ) ch_malloc( sizeof ( struct ldapmod ));
    ldm->mod_type = NULL;
    ldm->mod_bvalues = ( struct berval ** ) NULL;
    return( ldm );
}



/*
 * Free an ldapmod struct associated mod_bvalues.  NOTE - it is assumed
 * that mod_bvalues and mod_type contain pointers to the same block of memory
 * pointed to by the repl struct.  Therefore, it's not freed here.
 */
static void
free_ldapmod(
LDAPMod *ldm )
{
    int		i;

    if ( ldm == NULL ) {
	return;
    }
    if ( ldm->mod_bvalues != NULL ) {
	for ( i = 0; ldm->mod_bvalues[ i ] != NULL; i++ ) {
	    free( ldm->mod_bvalues[ i ] );
	}
	free( ldm->mod_bvalues );
    }
    free( ldm );
    return;
}


/*
 * Free an an array of LDAPMod pointers and the LDAPMod structs they point
 * to.
 */
static void
free_ldmarr(
LDAPMod **ldmarr )
{
    int	i;

    for ( i = 0; ldmarr[ i ] != NULL; i++ ) {
	free_ldapmod( ldmarr[ i ] );
    }
    free( ldmarr );
}


/*
 * Create a berval with a single value. 
 */
static struct berval **
make_singlevalued_berval( 
char	*value,
int	len )
{
    struct berval **p;

    p = ( struct berval ** ) ch_malloc( 2 * sizeof( struct berval * ));
    p[ 0 ] = ( struct berval * ) ch_malloc( sizeof( struct berval ));
    p[ 1 ] = NULL;
    p[ 0 ]->bv_val = value;
    p[ 0 ]->bv_len = len;
    return( p );
}


/*
 * Given a modification type (string), return an enumerated type.
 * Avoids ugly copy in op_ldap_modify - lets us use a switch statement
 * there.
 */
static int
getmodtype( 
char *type )
{
    if ( !strcmp( type, T_MODSEPSTR )) {
	return( T_MODSEP );
    }
    if ( !strcmp( type, T_MODOPADDSTR )) {
	return( T_MODOPADD );
    }
    if ( !strcmp( type, T_MODOPREPLACESTR )) {
	return( T_MODOPREPLACE );
    }
    if ( !strcmp( type, T_MODOPDELETESTR )) {
	return( T_MODOPDELETE );
    }
    if ( !strcmp( type, T_MODOPINCREMENTSTR )) {
	return( T_MODOPINCREMENT );
    }
    return( T_ERR );
}


/*
 * Perform an LDAP unbind operation.  If replica is NULL, or the
 * repl_ldp is NULL, just return LDAP_SUCCESS.  Otherwise, unbind,
 * set the ldp to NULL, and return the result of the unbind call.
 */
static int
do_unbind(
    Ri	*ri
)
{
    int		rc = LDAP_SUCCESS;

    if (( ri != NULL ) && ( ri->ri_ldp != NULL )) {
	rc = ldap_unbind( ri->ri_ldp );
	if ( rc != LDAP_SUCCESS ) {
	    Debug( LDAP_DEBUG_ANY,
		    "Error: do_unbind: ldap_unbind failed for %s:%d: %s\n",
		    ri->ri_hostname, ri->ri_port, ldap_err2string( rc ) );
	}
	ri->ri_ldp = NULL;
    }
    return rc;
}



/*
 * Perform an LDAP bind operation to the replication site given
 * by replica.  If replica->repl_ldp is non-NULL, then we unbind
 * from the replica before rebinding.  It should be safe to call
 * this to re-connect if the replica's connection goes away
 * for some reason.
 *
 * Returns 0 on success, -1 if an LDAP error occurred, and a return
 * code > 0 if some other error occurred, e.g. invalid bind method.
 * If an LDAP error occurs, the LDAP error is returned in lderr.
 */
static int
do_bind( 
    Ri	*ri,
    int	*lderr
)
{
    int		ldrc;
    int		do_tls = ri->ri_tls;

    *lderr = 0;

    if ( ri == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Error: do_bind: null ri ptr\n", 0, 0, 0 );
	return( BIND_ERR_BADRI );
    }

retry:
    if ( ri->ri_ldp != NULL ) {
	ldrc = ldap_unbind( ri->ri_ldp );
	if ( ldrc != LDAP_SUCCESS ) {
	    Debug( LDAP_DEBUG_ANY,
		    "Error: do_bind: ldap_unbind failed: %s\n",
		    ldap_err2string( ldrc ), 0, 0 );
	}
	ri->ri_ldp = NULL;
    }
    
	if ( ri->ri_uri != NULL ) { /* new URI style */
	    Debug( LDAP_DEBUG_ARGS, "Initializing session to %s\n",
		    ri->ri_uri, 0, 0 );

		ldrc = ldap_initialize( &(ri->ri_ldp), ri->ri_uri);

		if (ldrc != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_ANY, "Error: ldap_initialize(0, %s) failed: %s\n",
			ri->ri_uri, ldap_err2string(ldrc), 0 );
		return( BIND_ERR_OPEN );		
		}
	} else { /* old HOST style */
    Debug( LDAP_DEBUG_ARGS, "Initializing session to %s:%d\n",
	    ri->ri_hostname, ri->ri_port, 0 );

    ri->ri_ldp = ldap_init( ri->ri_hostname, ri->ri_port );
    if ( ri->ri_ldp == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Error: ldap_init(%s, %d) failed: %s\n",
			ri->ri_hostname, ri->ri_port, sys_errlist[ errno ] );
		return( BIND_ERR_OPEN );
    }
    }

	{	/* set version 3 */
		int err, version = LDAP_VERSION3;
		err = ldap_set_option(ri->ri_ldp,
			LDAP_OPT_PROTOCOL_VERSION, &version);

		if( err != LDAP_OPT_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"Error: ldap_set_option(%s, LDAP_OPT_VERSION, 3) failed!\n",
				ri->ri_hostname, NULL, NULL );

			ldap_unbind( ri->ri_ldp );
			ri->ri_ldp = NULL;
			return BIND_ERR_VERSION;
		}
	}

    /*
     * Set ldap library options to (1) not follow referrals, and 
     * (2) restart the select() system call.
     */
	{
		int err;
		err = ldap_set_option(ri->ri_ldp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);

		if( err != LDAP_OPT_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"Error: ldap_set_option(%s,REFERRALS, OFF) failed!\n",
				ri->ri_hostname, NULL, NULL );
			ldap_unbind( ri->ri_ldp );
			ri->ri_ldp = NULL;
			return BIND_ERR_REFERRALS;
		}
	}
	ldap_set_option(ri->ri_ldp, LDAP_OPT_RESTART, LDAP_OPT_ON);

	if( do_tls ) {
		int err = ldap_start_tls_s(ri->ri_ldp, NULL, NULL);

		if( err != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: ldap_start_tls failed: %s (%d)\n",
				ri->ri_tls == TLS_CRITICAL ? "Error" : "Warning",
				ldap_err2string( err ), err );

			if( ri->ri_tls == TLS_CRITICAL ) {
				*lderr = err;
				ldap_unbind( ri->ri_ldp );
				ri->ri_ldp = NULL;
				return BIND_ERR_TLS_FAILED;
			}
			do_tls = TLS_OFF;
			goto retry;
		}
	}

    switch ( ri->ri_bind_method ) {
    case LDAP_AUTH_SIMPLE:
	/*
	 * Bind with a plaintext password.
	 */
	Debug( LDAP_DEBUG_ARGS, "bind to %s:%d as %s (simple)\n",
		ri->ri_hostname, ri->ri_port, ri->ri_bind_dn );
	ldrc = ldap_simple_bind_s( ri->ri_ldp, ri->ri_bind_dn,
		ri->ri_password );
	if ( ldrc != LDAP_SUCCESS ) {
	    Debug( LDAP_DEBUG_ANY,
		    "Error: ldap_simple_bind_s for %s:%d failed: %s\n",
		    ri->ri_hostname, ri->ri_port, ldap_err2string( ldrc ));
	    *lderr = ldrc;
		ldap_unbind( ri->ri_ldp );
		ri->ri_ldp = NULL;
	    return( BIND_ERR_SIMPLE_FAILED );
	}
	break;

	case LDAP_AUTH_SASL:
	Debug( LDAP_DEBUG_ARGS, "bind to %s as %s via %s (SASL)\n",
		ri->ri_hostname,
		ri->ri_authcId ? ri->ri_authcId : "-",
		ri->ri_saslmech );

#ifdef HAVE_CYRUS_SASL
	if( ri->ri_secprops != NULL ) {
		int err = ldap_set_option(ri->ri_ldp,
			LDAP_OPT_X_SASL_SECPROPS, ri->ri_secprops);

		if( err != LDAP_OPT_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"Error: ldap_set_option(%s,SECPROPS,\"%s\") failed!\n",
				ri->ri_hostname, ri->ri_secprops, NULL );
			ldap_unbind( ri->ri_ldp );
			ri->ri_ldp = NULL;
			return BIND_ERR_SASL_FAILED;
		}
	}

	{
		void *defaults = lutil_sasl_defaults( ri->ri_ldp, ri->ri_saslmech,
		    ri->ri_realm, ri->ri_authcId, ri->ri_password, ri->ri_authzId );

		ldrc = ldap_sasl_interactive_bind_s( ri->ri_ldp, ri->ri_bind_dn,
		    ri->ri_saslmech, NULL, NULL,
		    LDAP_SASL_QUIET, lutil_sasl_interact, defaults );

		lutil_sasl_freedefs( defaults );
		if ( ldrc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "Error: LDAP SASL for %s:%d failed: %s\n",
			    ri->ri_hostname, ri->ri_port, ldap_err2string( ldrc ));
			*lderr = ldrc;
			ldap_unbind( ri->ri_ldp );
			ri->ri_ldp = NULL;
			return( BIND_ERR_SASL_FAILED );
		}
	}
	break;
#else
	Debug( LDAP_DEBUG_ANY,
		"Error: do_bind: SASL not supported %s:%d\n",
		 ri->ri_hostname, ri->ri_port, NULL );
	ldap_unbind( ri->ri_ldp );
	ri->ri_ldp = NULL;
	return( BIND_ERR_BAD_ATYPE );
#endif

    default:
	Debug(  LDAP_DEBUG_ANY,
		"Error: do_bind: unknown auth type \"%d\" for %s:%d\n",
		ri->ri_bind_method, ri->ri_hostname, ri->ri_port );
	ldap_unbind( ri->ri_ldp );
	ri->ri_ldp = NULL;
	return( BIND_ERR_BAD_ATYPE );
    }

	{
		int err;
		LDAPControl c;
		LDAPControl *ctrls[2];
		ctrls[0] = &c;
		ctrls[1] = NULL;

		c.ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		c.ldctl_value.bv_val = NULL;
		c.ldctl_value.bv_len = 0;
		c.ldctl_iscritical = 0;

		err = ldap_set_option(ri->ri_ldp, LDAP_OPT_SERVER_CONTROLS, &ctrls);

		if( err != LDAP_OPT_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "Error: "
				"ldap_set_option(%s, SERVER_CONTROLS, ManageDSAit) failed!\n",
				ri->ri_hostname, NULL, NULL );
			ldap_unbind( ri->ri_ldp );
			ri->ri_ldp = NULL;
			return BIND_ERR_MANAGEDSAIT;
		}
	}

	return( BIND_OK );
}





/*
 * For debugging.  Print the contents of an ldmarr array.
 */
#ifdef SLAPD_UNUSED
static void
dump_ldm_array(
    LDAPMod **ldmarr
)
{
    int			 i, j;
    LDAPMod		*ldm;
    struct berval	*b;
    char		*msgbuf;

    for ( i = 0; ldmarr[ i ] != NULL; i++ ) {
	ldm = ldmarr[ i ];
	Debug( LDAP_DEBUG_TRACE,
		"Trace (%ld): *** ldmarr[ %d ] contents:\n",
		(long) getpid(), i, 0 );
	Debug( LDAP_DEBUG_TRACE,
		"Trace (%ld): *** ldm->mod_op: %d\n",
		(long) getpid(), ldm->mod_op, 0 );
	Debug( LDAP_DEBUG_TRACE,
		"Trace (%ld): *** ldm->mod_type: %s\n",
		(long) getpid(), ldm->mod_type, 0 );
	if ( ldm->mod_bvalues != NULL ) {
	    for ( j = 0; ( b = ldm->mod_bvalues[ j ] ) != NULL; j++ ) {
		msgbuf = ch_malloc( b->bv_len + 512 );
		sprintf( msgbuf, "***** bv[ %d ] len = %ld, val = <%s>",
			j, b->bv_len, b->bv_val );
		Debug( LDAP_DEBUG_TRACE,
			"Trace (%ld):%s\n", (long) getpid(), msgbuf, 0 );
		free( msgbuf );
	    }
	}
    }
}
#endif

/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
 * (as part of U-MICH LDAP).
 */

/* 
 * re.c - routines which deal with Re (Replication entry) structures.
 * An Re struct is an in-core representation of one replication to
 * be performed, along with member functions which are called by other
 * routines.  The Re struct is defined in slurp.h.
 */


#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/ctype.h>

#include "../slapd/slap.h"

#include "slurp.h"
#include "globals.h"
#include "lutil.h"

/* Forward references */
static Rh 	*get_repl_hosts LDAP_P(( char *, int *, char ** ));
static int	gettype LDAP_P(( char * ));
static int	getchangetype LDAP_P(( char * ));
static int	Re_parse LDAP_P(( Re *re, char *replbuf ));
static void 	Re_dump LDAP_P(( Re *re, FILE *fp ));
static void	warn_unknown_replica LDAP_P(( char *, int port ));

/* Globals, scoped within this file */
static int	nur = 0;	/* Number of unknown replicas */
static Rh 	*ur = NULL;	/* array of unknown replica names */


/*
 * Return the next Re in a linked list.
 */
static Re *
Re_getnext(
    Re	*re
)
{
    return(( re == NULL ) ? NULL :  re->re_next );
}




/*
 * Free an Re
 * ??? Something should apparently return nonzero here, but I dont know what.
 */
static int
Re_free(
    Re	*re
)
{
    Rh	*rh;
    Mi	*mi;
    int	i;

    if ( re == NULL ) {
	return 0;
    }
    if ( re->re_refcnt > 0 ) {
	Debug( LDAP_DEBUG_ANY,
		"Warning: freeing re (dn: %s) with nonzero refcnt\n",
		re->re_dn, 0, 0 );
    }

    ldap_pvt_thread_mutex_destroy( &re->re_mutex );

    if (( rh = re->re_replicas ) != NULL ) {
	for ( i = 0; rh[ i ].rh_hostname != NULL; i++ ) {
	    free( rh[ i ].rh_hostname );
	}
	free( rh );
    }
    ch_free( re->re_dn );
    if (( mi = re->re_mods ) != NULL ) {
	for ( i = 0; mi[ i ].mi_type != NULL; i++ ) {
	    free( mi[ i ].mi_type );
	    ch_free( mi[ i ].mi_val );
	}
	free( mi );
    }
    free( re );
    return 0;
}




/*
 * Read a buffer of data from a replication log file and fill in
 * an (already allocated) Re.
 */

#define	BEGIN		0
#define	GOT_DN		1
#define	GOT_TIME	2
#define	GOT_CHANGETYPE	4
#define	GOT_ALL		( GOT_DN | GOT_TIME | GOT_CHANGETYPE )

static int
Re_parse(
    Re		*re,
    char	*replbuf
)
{
    int			state;
    int			nml;
    char		*buf, *rp, *p;
    size_t		buflen;
    char		*type, *value;
    ber_len_t	len;
    int			nreplicas;

    if ( re == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Re_parse: error: re is NULL\n", 0, 0, 0 );
	return -1;
    }
    if ( replbuf == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Re_parse: error: replbuf is NULL\n", 0, 0, 0 );
	return -1;
    }

    state = BEGIN;
    nml = 0;	/* number of modification information entries */
    rp = replbuf;

    re->re_replicas = get_repl_hosts( replbuf, &nreplicas, &rp );
    re->re_refcnt = sglob->num_replicas;

    for (;;) {
	if (( state == GOT_ALL ) || ( buf = ldif_getline( &rp )) == NULL ) {
	    break;
	}
	/*
	 * If we're processing a rejection log, then the first line
	 * of each replication record will begin with "ERROR" - just
	 * ignore it.
	 */
	if ( strncmp( buf, ERROR_STR, strlen( ERROR_STR )) == 0 ) {
	    continue;
	}
	buflen = strlen( buf );
	if ( ldif_parse_line( buf, &type, &value, &len ) < 0 ) {
	    Debug( LDAP_DEBUG_ANY,
		    "Error: Re_parse: malformed replog file\n",
		    0, 0, 0 );
	    return -1;
	}
	switch ( gettype( type )) {
	case T_CHANGETYPE:
	    re->re_changetype = getchangetype( value );
	    state |= GOT_CHANGETYPE;
	    break;
	case T_TIME: {
	    unsigned long	t;

	    if (( p = strchr( value, '.' )) != NULL ) {
		/* there was a sequence number */
		*p++ = '\0';
	    }
	    if ( lutil_atoul( &t, value ) != 0 ) {
	        Debug( LDAP_DEBUG_ANY,
		        "Error: Re_parse: unable to parse timestamp \"%s\"\n",
		        value, 0, 0 );
	        return -1;
	    }
	    re->re_timestamp = (time_t)t;
	    if ( p != NULL && isdigit( (unsigned char) *p )
		&& lutil_atoi( &re->re_seq, p ) != 0 )
	    {
	        Debug( LDAP_DEBUG_ANY,
		        "Error: Re_parse: unable to parse sequence number \"%s\"\n",
		        p, 0, 0 );
	        return -1;
	    }
	    state |= GOT_TIME;
	    } break;
	case T_DN:
	    re->re_dn = ch_malloc( len + 1 );
		AC_MEMCPY( re->re_dn, value, len );
		re->re_dn[ len ]='\0';
	    state |= GOT_DN;
	    break;
	default:
	    if ( !( state == GOT_ALL )) {
		Debug( LDAP_DEBUG_ANY,
			"Error: Re_parse: bad type <%s>\n",
			type, 0, 0 );
		free( type );
		free( value );
		return -1;
	    }
	}
	free( type );
	free( value );
    }

    if ( state != GOT_ALL ) {
	Debug( LDAP_DEBUG_ANY,
		"Error: Re_parse: malformed replog file\n",
		0, 0, 0 );
	return -1;
    }

    for (;;) {
	char *const dash = "-";

	if (( buf = ldif_getline( &rp )) == NULL ) {
	    break;
	}
	buflen = strlen( buf );
	if (( buflen == 1 ) && ( buf[ 0 ] == '-' )) {
	    type  = dash;
	    value = NULL;
	} else {
	    if ( ldif_parse_line( buf, &type, &value, &len ) < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: malformed replog line \"%s\"\n",
			buf, 0, 0 );
		return -1;
	    }
	}
	re->re_mods = ( Mi  *) ch_realloc( (char *) re->re_mods,
	    sizeof( Mi ) * ( nml + 2 ));
	re->re_mods[ nml ].mi_type = strdup( type );
	if ( value != NULL ) {
	    re->re_mods[ nml ].mi_val = ch_malloc( len + 1 );
		AC_MEMCPY( re->re_mods[ nml ].mi_val, value, len );
		re->re_mods[ nml ].mi_val[ len ] = '\0';
	    re->re_mods[ nml ].mi_len = len;
	} else {
	    re->re_mods[ nml ].mi_val = NULL;
	    re->re_mods[ nml ].mi_len = 0;
	}
	re->re_mods[ nml + 1 ].mi_type = NULL;
	re->re_mods[ nml + 1 ].mi_val = NULL;
	nml++;

	if ( type != dash )
		free( type );
	if ( value != NULL )
		free( value );
    }
    return 0;
}



/*
 * Extract the replication hosts from a repl buf.  Check to be sure that
 * each replica host and port number are ones we know about (that is, they're
 * in the slapd config file we read at startup).  Without that information
 * from the config file, we won't have the appropriate credentials to
 * make modifications.  If there are any unknown replica names, don't
 * add them the the Re struct.  Instead, log a warning message.
 */
static Rh *
get_repl_hosts(
    char	*replbuf,
    int		*r_nreplicas,
    char	**r_rp
)
{
    char		*type, *value, *line, *p;
    Rh			*rh = NULL;
    int			nreplicas;
	ber_len_t	len;
    int			port;
    int			repl_ok;
    int			i;

    if ( replbuf == NULL ) {
	return( NULL );
    }

    nreplicas = 0;

    /*
     * Get the host names of the replicas
     */
    *r_nreplicas = 0;
    *r_rp = replbuf;
    for (;;) {
	/* If this is a reject log, we need to skip over the ERROR: line */
	if ( !strncmp( *r_rp, ERROR_STR, strlen( ERROR_STR ))) {
	    line = ldif_getline( r_rp );
	    if ( line == NULL ) {
		break;
	    }
	}
	if ( strncasecmp( *r_rp, "replica:", 7 )) {
	    break;
	}
	line = ldif_getline( r_rp );
	if ( line == NULL ) {
	    break;
	}
	if ( ldif_parse_line( line, &type, &value, &len ) < 0 ) {
	    return( NULL );
	}
	port = LDAP_PORT;
	if (( p = strchr( value, ':' )) != NULL ) {
	    *p = '\0';
	    p++;
	    if ( *p != '\0' && lutil_atoi( &port, p ) != 0 ) {
		return( NULL );
	    }
	}

	/* Verify that we've heard of this replica before */
	repl_ok = 0;
	for ( i = 0; i < sglob->num_replicas; i++ ) {
	    if ( strcmp( sglob->replicas[ i ]->ri_hostname, value )) {
		continue;
	    }
	    if ( sglob->replicas[ i ]->ri_port == port ) {
		repl_ok = 1;
		break;
	    }
	}
	free( type );
	if ( !repl_ok ) {
	    warn_unknown_replica( value, port );
	    free( value );
	    continue;
	}

	rh = (Rh *) ch_realloc((char *) rh, ( nreplicas + 2 ) * sizeof( Rh ));
	if ( rh == NULL ) {
	    Debug( LDAP_DEBUG_ANY, "Out of memory in get_repl_hosts\n",
		    0, 0, 0 );
	    return NULL;
	}
	rh[ nreplicas ].rh_hostname = strdup( value );
	rh[ nreplicas ].rh_port = port;
	nreplicas++;

	free( value );
    }

    if ( nreplicas == 0 ) {
	return( NULL );
    }

    rh[ nreplicas ].rh_hostname = NULL;
    *r_nreplicas = nreplicas;

    return( rh );
}





/*
 * Convert "type" to an int.
 */
static int
gettype(
    char	*type
)
{
    if ( !strcmp( type, T_CHANGETYPESTR )) {
	return( T_CHANGETYPE );
    }
    if ( !strcmp( type, T_TIMESTR )) {
	return( T_TIME );
    }
    if ( !strcmp( type, T_DNSTR )) {
	return( T_DN );
    }
    return( T_ERR );
}



/*
 * Convert "changetype" to an int.
 */
static int
getchangetype(
    char	*changetype
)
{
    if ( !strcmp( changetype, T_ADDCTSTR )) {
	return( T_ADDCT );
    }
    if ( !strcmp( changetype, T_MODIFYCTSTR )) {
	return( T_MODIFYCT );
    }
    if ( !strcmp( changetype, T_DELETECTSTR )) {
	return( T_DELETECT );
    }
    if ( !strcmp( changetype, T_MODRDNCTSTR )) {
	return( T_MODRDNCT );
    }
    return( T_ERR );
}




#if 0
/*
 * Find the first line which is not a "replica:" line in buf.
 * Returns a pointer to the line.  Returns NULL if there are
 * only "replica:" lines in buf.
 */
static char *
skip_replica_lines(
    char	*buf
)
{
    char *p = buf;
    for (;;) {
	if ( strncasecmp( p, "replica:", 8 )) {
	    return( p );
	}
	while (( *p != '\0' )  && ( *p != '\n' )) {
	    p++;
	}
	if ( *p == '\0' ) {
	    return ( NULL );
	} else {
	    p++;
	}
    }
}
#endif /* 0 */




/*
 * For debugging purposes: dump the contents of a replication entry.
 * to the given stream.
 */
static void
Re_dump(
    Re		*re,
    FILE	*fp
)
{
    int i;
    Mi *mi;

    if ( re == NULL ) {
	Debug( LDAP_DEBUG_TRACE, "Re_dump: re is NULL\n", 0, 0, 0 );
	return;
    }
    fprintf( fp, "Re_dump: ******\n" );
    fprintf( fp, "re_refcnt: %d\n", re->re_refcnt );
    fprintf( fp, "re_timestamp: %ld\n", (long) re->re_timestamp );
    fprintf( fp, "re_seq: %d\n", re->re_seq );
    for ( i = 0; re->re_replicas && re->re_replicas[ i ].rh_hostname != NULL;
		i++ ) {
	fprintf( fp, "re_replicas[%d]: %s:%d\n", 
		i, re->re_replicas[ i ].rh_hostname,
		re->re_replicas[ i ].rh_port );
    }
    fprintf( fp, "re_dn: %s\n", re->re_dn );
    switch ( re->re_changetype ) {
    case T_ADDCT:
	fprintf( fp, "re_changetype: add\n" );
	break;
    case T_MODIFYCT:
	fprintf( fp, "re_changetype: modify\n" );
	break;
    case T_DELETECT:
	fprintf( fp, "re_changetype: delete\n" );
	break;
    case T_MODRDNCT:
	fprintf( fp, "re_changetype: modrdn\n" );
	break;
    default:
	fprintf( fp, "re_changetype: (unknown, type = %d\n",
		re->re_changetype );
    }
    if ( re->re_mods == NULL ) {
	fprintf( fp, "re_mods: (none)\n" );
    } else {
	mi = re->re_mods;
	fprintf( fp, "re_mods:\n" );
	for ( i = 0; mi[ i ].mi_type != NULL; i++ ) {
	    fprintf( fp, "  %s, \"%s\", (%d bytes)\n",
		    mi[ i ].mi_type,
		    mi[ i ].mi_val == NULL ?  "(null)" : mi[ i ].mi_val,
		    mi[ i ].mi_len );
	}
    }
    return;
}


/* 
 * Given an Ri, an Re, and a file pointer, write a replication record to
 * the file pointer.  If ri is NULL, then include all replicas in the
 * output.  If ri is non-NULL, then only include a single "replica:" line
 * (used when writing rejection records).  Returns 0 on success, -1
 * on failure.  Note that Re_write will not write anything out if the
 * refcnt is zero.
 */
static int
Re_write(
    Ri		*ri,
    Re		*re,
    FILE	*fp )
{
    int		i;
    char	*s;
    int		rc = 0;

    if ( re == NULL || fp == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Internal error: Re_write: NULL argument\n",
		0, 0, 0 );
	return -1;
    }

    if ( re->re_refcnt < 1 ) {
	return 0;		/* this is not an error */
    }

    if ( ri != NULL ) {		/* write a single "replica:" line */
	if ( ri->ri_port != 0 ) {
	    rc = fprintf( fp, "replica: %s:%d\n", ri->ri_hostname,
		    ri->ri_port );
	} else {
	    rc = fprintf( fp, "replica: %s\n", ri->ri_hostname );
	}
	if ( rc < 0 ) {
	    rc = -1;
	    goto bad;
	}
	rc = 0;

    } else {			/* write multiple "replica:" lines */
	for ( i = 0; re->re_replicas && re->re_replicas[ i ].rh_hostname != NULL; i++ ) {
	    if ( fprintf( fp, "replica: %s:%d\n",
		    re->re_replicas[ i ].rh_hostname,
		    re->re_replicas[ i ].rh_port ) < 0 ) {
		rc = -1;
		goto bad;
	    }
	}
    }
    if ( fprintf( fp, "time: %ld.%d\n", (long) re->re_timestamp, re->re_seq ) < 0 ) {
	rc = -1;
	goto bad;
    }
    if ( fprintf( fp, "dn: %s\n", re->re_dn ) < 0 ) {
	rc = -1;
	goto bad;
    }
    if ( fprintf( fp, "changetype: " ) < 0 ) {
	rc = -1;
	goto bad;
    }
    switch ( re->re_changetype ) {
    case T_ADDCT:
	s = T_ADDCTSTR;
	break;
    case T_MODIFYCT:
	s = T_MODIFYCTSTR;
	break;
    case T_DELETECT:
	s = T_DELETECTSTR;
	break;
    case T_MODRDNCT:
	s = T_MODRDNCTSTR;
	break;
    default:
	s = "IllegalModifyType!!!";
    }
    if ( fprintf( fp, "%s\n", s ) < 0 ) {
	rc = -1;
	goto bad;
    }
    for ( i = 0; (( re->re_mods != NULL ) &&
	    ( re->re_mods[ i ].mi_type != NULL )); i++ ) {
	if ( !strcmp( re->re_mods[ i ].mi_type, T_MODSEPSTR )) {
	    if ( fprintf( fp, "%s\n", T_MODSEPSTR ) < 0 ) {
		rc = -1;
		goto bad;
	    }
	} else {
	    char *obuf;
	    obuf = ldif_put( LDIF_PUT_VALUE,
			re->re_mods[ i ].mi_type,
		    re->re_mods[ i ].mi_val ? re->re_mods[ i ].mi_val : "",
		    re->re_mods[ i ].mi_len );
	    if ( fputs( obuf, fp ) < 0 ) {
		rc = -1;
		free( obuf );
		goto bad;
	    } else {
		ber_memfree( obuf );
	    }
	}
    }
    if ( fprintf( fp, "\n" ) < 0 ) {
	rc = -1;
	goto bad;
    }
    if ( fflush( fp ) != 0 ) {
	rc = -1;
	goto bad;
    }
bad:
    if ( rc != 0 ) {
	Debug( LDAP_DEBUG_ANY, "Error while writing: %s\n",
		sys_errlist[ errno ], 0, 0 );
    }
    return rc;
}




/*
 * Decrement the refcnt.  Locking handled internally.
 */
static int
Re_decrefcnt(
    Re	*re
)
{
    re->re_lock( re );
    re->re_refcnt--;
    re->re_unlock( re );
    return 0;
}



/*
 * Get the refcnt.  Locking handled internally.
 */
static int
Re_getrefcnt(
    Re	*re
)
{
    int	ret;

    re->re_lock( re );
    ret = re->re_refcnt;
    re->re_unlock( re );
    return ret;
}
    
    



/*
 * Lock this replication entry
 */
static int
Re_lock(
    Re	*re
)
{
    return( ldap_pvt_thread_mutex_lock( &re->re_mutex ));
}




/*
 * Unlock this replication entry
 */
static int
Re_unlock(
    Re	*re
)
{
    return( ldap_pvt_thread_mutex_unlock( &re->re_mutex ));
}




/* 
 * Instantiate and initialize an Re.
 */
int
Re_init(
    Re **re
)
{
    /* Instantiate */
    (*re) = (Re *) malloc( sizeof( Re ));
    if ( *re == NULL ) {
	return -1;
    }

    /* Fill in the member function pointers */
    (*re)->re_free = Re_free;
    (*re)->re_getnext = Re_getnext;
    (*re)->re_parse = Re_parse;
    (*re)->re_write = Re_write;
    (*re)->re_dump = Re_dump;
    (*re)->re_lock = Re_lock;
    (*re)->re_unlock = Re_unlock;
    (*re)->re_decrefcnt = Re_decrefcnt;
    (*re)->re_getrefcnt = Re_getrefcnt;

    /* Initialize private data */
   (*re)->re_refcnt = sglob->num_replicas;
   (*re)->re_timestamp = (time_t) 0L;
   (*re)->re_replicas = NULL;
   (*re)->re_dn = NULL;
   (*re)->re_changetype = 0;
   (*re)->re_seq = 0;
   (*re)->re_mods = NULL;
   (*re)->re_next = NULL;

   ldap_pvt_thread_mutex_init( &((*re)->re_mutex) );
   return 0;
}




/*
 * Given a host and port, generate a warning message iff we haven't already
 * generated a message for this host:port combination.
 */
static void
warn_unknown_replica( 
    char	*host,
    int		port
)
{
    int	found = 0;
    int	i;

    for ( i = 0; i < nur; i++ ) {
	if ( strcmp( ur[ i ].rh_hostname, host )) {
	    continue;
	}
	if ( ur[ i ].rh_port == port ) {
	    found = 1;
	    break;
	}
    }
    if ( !found ) {
	Debug( LDAP_DEBUG_ANY,
		"Warning: unknown replica %s:%d found in replication log\n",
		host, port, 0 );
	nur++;
	ur = (Rh *) ch_realloc( (char *) ur, ( nur * sizeof( Rh )));
	ur[ nur - 1 ].rh_hostname = strdup( host );
	ur[ nur - 1 ].rh_port = port;
    }
}

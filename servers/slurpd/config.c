/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */


/*
 * config.c - configuration file handling routines
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/ctype.h>

#include <ldap.h>

#include "slurp.h"
#include "globals.h"

#define MAXARGS	100

/* Forward declarations */
static void	add_replica LDAP_P(( char **, int ));
static int	parse_replica_line LDAP_P(( char **, int, Ri *));
static void	parse_line LDAP_P(( char *, int *, char ** ));
static char	*getline LDAP_P(( FILE * ));
static char	*strtok_quote LDAP_P(( char *, char * ));

/* current config file line # */
static int	lineno;



/*
 * Read the slapd config file, looking only for config options we're
 * interested in.  Since we haven't detached from the controlling
 * terminal yet, we just perror() and fprintf here.
 */
int
slurpd_read_config(
    char	*fname
)
{
    FILE	*fp;
    char	*line;
    int		cargc;
    char	*cargv[MAXARGS];

    Debug( LDAP_DEBUG_CONFIG, "Config: opening config file \"%s\"\n",
	    fname, 0, 0 );

    if ( (fp = fopen( fname, "r" )) == NULL ) {
	perror( fname );
	exit( EXIT_FAILURE );
    }

    lineno = 0;
    while ( (line = getline( fp )) != NULL ) {
	/* skip comments and blank lines */
	if ( line[0] == '#' || line[0] == '\0' ) {
	    continue;
	}

	Debug( LDAP_DEBUG_CONFIG, "Config: (%s)\n", line, 0, 0 );

	parse_line( line, &cargc, cargv );

	if ( cargc < 1 ) {
	    fprintf( stderr, "line %d: bad config line (ignored)\n", lineno );
	    continue;
	}

	/* replication log file to which changes are appended */
	if ( strcasecmp( cargv[0], "replogfile" ) == 0 ) {
	    /* 
	     * if slapd_replogfile has a value, the -r option was given,
	     * so use that value.  If slapd_replogfile has length == 0,
	     * then we should use the value in the config file we're reading.
	     */
	    if ( sglob->slapd_replogfile[ 0 ] == '\0' ) {
		if ( cargc < 2 ) {
		    fprintf( stderr,
			"line %d: missing filename in \"replogfile ",
			lineno );
		    fprintf( stderr, "<filename>\" line\n" );
		    exit( EXIT_FAILURE );
		} else if ( cargc > 2 && *cargv[2] != '#' ) {
		    fprintf( stderr,
			"line %d: extra cruft at the end of \"replogfile %s\"",
			lineno, cargv[1] );
		    fprintf( stderr, "line (ignored)\n" );
		}
		strcpy( sglob->slapd_replogfile, cargv[1] );
	    }
	} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
	    add_replica( cargv, cargc );
	}
    }
    fclose( fp );
    Debug( LDAP_DEBUG_CONFIG,
	    "Config: ** configuration file successfully read and parsed\n",
	    0, 0, 0 );
    return 0;
}




/*
 * Parse one line of input.
 */
static void
parse_line(
    char	*line,
    int		*argcp,
    char	**argv
)
{
    char *	token;

    *argcp = 0;
    for ( token = strtok_quote( line, " \t" ); token != NULL;
	token = strtok_quote( NULL, " \t" ) ) {
	argv[(*argcp)++] = token;
    }
    argv[*argcp] = NULL;
}




static char *
strtok_quote(
    char *line,
    char *sep
)
{
    int		inquote;
    char	*tmp;
    static char	*next;

    if ( line != NULL ) {
	next = line;
    }
    while ( *next && strchr( sep, *next ) ) {
	next++;
    }

    if ( *next == '\0' ) {
	next = NULL;
	return( NULL );
    }
    tmp = next;

    for ( inquote = 0; *next; ) {
	switch ( *next ) {
	case '"':
	    if ( inquote ) {
		inquote = 0;
	    } else {
		inquote = 1;
	    }
	    AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
	    break;

	case '\\':
	    if ( next[1] )
		AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
	    next++;		/* dont parse the escaped character */
	    break;

	default:
	    if ( ! inquote ) {
		if ( strchr( sep, *next ) != NULL ) {
		    *next++ = '\0';
		    return( tmp );
		}
	    }
	    next++;
	    break;
	}
    }

    return( tmp );
}

#define CATLINE( buf )	{ \
    int	len; \
    len = strlen( buf ); \
    while ( lcur + len + 1 > lmax ) { \
	lmax += BUFSIZ; \
	line = (char *) ch_realloc( line, lmax ); \
    } \
    strcpy( line + lcur, buf ); \
    lcur += len; \
}



/*
 * Get a line of input.
 */
static char *
getline(
    FILE *fp
)
{
    char	*p;
    static char	buf[BUFSIZ];
    static char	*line;
    static int	lmax, lcur;

    lcur = 0;
    CATLINE( buf );
    while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
	if ( (p = strchr( buf, '\n' )) != NULL ) {
	    *p = '\0';
	}
	lineno++;
	if ( ! isspace( (unsigned char) buf[0] ) ) {
	    return( line );
	}

	CATLINE( buf );
    }
    buf[0] = '\0';

    return( line[0] ? line : NULL );
}


/*
 * Add a node to the array of replicas.
 */
static void
add_replica(
    char	**cargv,
    int		cargc
)
{
    int	nr;

    nr = ++sglob->num_replicas;
    sglob->replicas = (Ri **) ch_realloc( sglob->replicas,
	    ( nr + 1 )  * sizeof( Re * ));
    if ( sglob->replicas == NULL ) {
	fprintf( stderr, "out of memory, add_replica\n" );
	exit( EXIT_FAILURE );
    }
    sglob->replicas[ nr ] = NULL; 

    if ( Ri_init( &(sglob->replicas[ nr - 1 ])) < 0 ) {
	fprintf( stderr, "out of memory, Ri_init\n" );
	exit( EXIT_FAILURE );
    }
    if ( parse_replica_line( cargv, cargc,
	    sglob->replicas[ nr - 1] ) < 0 ) {
	/* Something bad happened - back out */
	fprintf( stderr,
	    "Warning: failed to add replica \"%s:%d - ignoring replica\n",
	    sglob->replicas[ nr - 1 ]->ri_hostname == NULL ?
	    "(null)" : sglob->replicas[ nr - 1 ]->ri_hostname,
	    sglob->replicas[ nr - 1 ]->ri_port );
	sglob->replicas[ nr - 1] = NULL;
	sglob->num_replicas--;
    } else {
	Debug( LDAP_DEBUG_CONFIG,
		"Config: ** successfully added replica \"%s:%d\"\n",
		sglob->replicas[ nr - 1 ]->ri_hostname == NULL ?
		"(null)" : sglob->replicas[ nr - 1 ]->ri_hostname,
		sglob->replicas[ nr - 1 ]->ri_port, 0 );
	sglob->replicas[ nr - 1]->ri_stel =
		sglob->st->st_add( sglob->st,
		sglob->replicas[ nr - 1 ] );
	if ( sglob->replicas[ nr - 1]->ri_stel == NULL ) {
	    fprintf( stderr, "Failed to add status element structure\n" );
	    exit( EXIT_FAILURE );
	}
    }
}



/* 
 * Parse a "replica" line from the config file.  replica lines should be
 * in the following format:
 * replica    host=<hostname:portnumber> binddn=<binddn>
 *            bindmethod="simple" credentials=<creds>
 *
 * where:
 * <hostname:portnumber> describes the host name and port number where the
 * replica is running,
 *
 * <binddn> is the DN to bind to the replica slapd as,
 *
 * bindmethod is "simple", and
 *
 * <creds> are the credentials (e.g. password) for binddn.  <creds> are
 * only used for bindmethod=simple.  
 *
 * The "replica" config file line may be split across multiple lines.  If
 * a line begins with whitespace, it is considered a continuation of the
 * previous line.
 */
#define	GOT_HOST	1
#define	GOT_DN		2
#define	GOT_METHOD	4
#define	GOT_ALL		( GOT_HOST | GOT_DN | GOT_METHOD )
#define	GOT_MECH	8

static int
parse_replica_line( 
    char	**cargv,
    int		cargc,
    Ri		*ri
)
{
    int		gots = 0;
    int		i;
    char	*hp, *val;

    for ( i = 1; i < cargc; i++ ) {
	if ( !strncasecmp( cargv[ i ], HOSTSTR, strlen( HOSTSTR ))) {
	    val = cargv[ i ] + strlen( HOSTSTR ) + 1;
	    if (( hp = strchr( val, ':' )) != NULL ) {
		*hp = '\0';
		hp++;
		ri->ri_port = atoi( hp );
	    }
	    if ( ri->ri_port <= 0 ) {
		ri->ri_port = 0;
	    }
	    ri->ri_hostname = strdup( val );
	    gots |= GOT_HOST;
	} else if ( !strncasecmp( cargv[ i ], TLSSTR, strlen( TLSSTR ))) {
	    val = cargv[ i ] + strlen( TLSSTR ) + 1;
		if( !strcasecmp( val, TLSCRITICALSTR ) ) {
			ri->ri_tls = TLS_CRITICAL;
		} else {
			ri->ri_tls = TLS_ON;
		}
	} else if ( !strncasecmp( cargv[ i ],
		BINDDNSTR, strlen( BINDDNSTR ))) { 
	    val = cargv[ i ] + strlen( BINDDNSTR ) + 1;
	    ri->ri_bind_dn = strdup( val );
	    gots |= GOT_DN;
	} else if ( !strncasecmp( cargv[ i ], BINDMETHSTR,
		strlen( BINDMETHSTR ))) {
	    val = cargv[ i ] + strlen( BINDMETHSTR ) + 1;
	    if ( !strcasecmp( val, KERBEROSSTR )) {
	    fprintf( stderr, "Error: a bind method of \"kerberos\" was\n" );
	    fprintf( stderr, "specified in the slapd configuration file.\n" );
	    fprintf( stderr, "slurpd no longer supports Kerberos.\n" );
	    exit( EXIT_FAILURE );
	    } else if ( !strcasecmp( val, SIMPLESTR )) {
		ri->ri_bind_method = AUTH_SIMPLE;
		gots |= GOT_METHOD;
	    } else if ( !strcasecmp( val, SASLSTR )) {
		ri->ri_bind_method = AUTH_SASL;
		gots |= GOT_METHOD;
	    } else {
		ri->ri_bind_method = -1;
	    }
	} else if ( !strncasecmp( cargv[ i ], SASLMECHSTR, strlen( SASLMECHSTR ))) {
	    val = cargv[ i ] + strlen( SASLMECHSTR ) + 1;
	    gots |= GOT_MECH;
	    ri->ri_saslmech = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], CREDSTR, strlen( CREDSTR ))) {
	    val = cargv[ i ] + strlen( CREDSTR ) + 1;
	    ri->ri_password = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], SECPROPSSTR, strlen( SECPROPSSTR ))) {
	    val = cargv[ i ] + strlen( SECPROPSSTR ) + 1;
	    ri->ri_secprops = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], REALMSTR, strlen( REALMSTR ))) {
	    val = cargv[ i ] + strlen( REALMSTR ) + 1;
	    ri->ri_realm = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], AUTHCSTR, strlen( AUTHCSTR ))) {
	    val = cargv[ i ] + strlen( AUTHCSTR ) + 1;
	    ri->ri_authcId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], OLDAUTHCSTR, strlen( OLDAUTHCSTR ))) {
	    /* Old authcID is provided for some backwards compatibility */
	    val = cargv[ i ] + strlen( OLDAUTHCSTR ) + 1;
	    ri->ri_authcId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], AUTHZSTR, strlen( AUTHZSTR ))) {
	    val = cargv[ i ] + strlen( AUTHZSTR ) + 1;
	    ri->ri_authzId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], SRVTABSTR, strlen( SRVTABSTR ))) {
	    val = cargv[ i ] + strlen( SRVTABSTR ) + 1;
	    if ( ri->ri_srvtab != NULL ) {
		free( ri->ri_srvtab );
	    }
	    ri->ri_srvtab = strdup( val );
	} else {
	    fprintf( stderr, 
		    "Error: parse_replica_line: unknown keyword \"%s\"\n",
		    cargv[ i ] );
	}
    }
    
	if ( ri->ri_bind_method == AUTH_SASL) {
		if ((gots & GOT_MECH) == 0) {
			fprintf( stderr, "Error: \"replica\" line needs SASLmech flag in " );
			fprintf( stderr, "slapd config file, line %d\n", lineno );
			return -1;
		}
	}
	else if ( gots != GOT_ALL ) {
		fprintf( stderr, "Error: Malformed \"replica\" line in slapd " );
		fprintf( stderr, "config file, line %d\n", lineno );
		return -1;
	}
    return 0;
}


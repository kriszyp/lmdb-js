/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * Portions Copyright 2003 Mark Benson.
 * Portions Copyright 2002 John Morrissey.
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
 * (as part of U-MICH LDAP).  Additional signficant contributors
 * include:
 *    John Morrissey
 *    Mark Benson
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
#include <lutil.h>

#include "slurp.h"
#include "globals.h"

#define ARGS_STEP	512

/* Forward declarations */
static void	add_replica LDAP_P(( char **, int ));
static int	parse_replica_line LDAP_P(( char **, int, Ri *));
static void	parse_line LDAP_P(( char * ));
static char	*slurpd_getline LDAP_P(( FILE * ));
static char	*strtok_quote LDAP_P(( char *, char * ));

int	cargc = 0, cargv_size = 0;
char	**cargv;
/* current config file line # */
static int	lineno;

char *slurpd_pid_file = NULL;
char *slurpd_args_file = NULL;

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

	if ( cargv == NULL ) {
	cargv = ch_calloc( ARGS_STEP + 1, sizeof(*cargv) );
	cargv_size = ARGS_STEP + 1;
	}

    Debug( LDAP_DEBUG_CONFIG, "Config: opening config file \"%s\"\n",
	    fname, 0, 0 );

    if ( (fp = fopen( fname, "r" )) == NULL ) {
	perror( fname );
	exit( EXIT_FAILURE );
    }

    lineno = 0;
    while ( (line = slurpd_getline( fp )) != NULL ) {
	/* skip comments and blank lines */
	if ( line[0] == '#' || line[0] == '\0' ) {
	    continue;
	}

	Debug( LDAP_DEBUG_CONFIG, "Config: (%s)\n", line, 0, 0 );

	parse_line( line );

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
		LUTIL_SLASHPATH( cargv[1] );
		strcpy( sglob->slapd_replogfile, cargv[1] );
	    }
	} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
	    add_replica( cargv, cargc );
	    
	    /* include another config file */
	} else if ( strcasecmp( cargv[0], "include" ) == 0 ) {
	    char *savefname;
	    int savelineno;

            if ( cargc < 2 ) {
                Debug( LDAP_DEBUG_ANY,
        "%s: line %d: missing filename in \"include <filename>\" line\n",
                        fname, lineno, 0 );
		
                return( 1 );
            }
	    LUTIL_SLASHPATH( cargv[1] );
	    savefname = strdup( cargv[1] );
	    savelineno = lineno;
	    
	    if ( slurpd_read_config( savefname ) != 0 ) {
	        return( 1 );
	    }
		
	    free( savefname );
	    lineno = savelineno - 1;

	} else if ( strcasecmp( cargv[0], "replica-pidfile" ) == 0 ) {
		if ( cargc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"replica-pidfile <file>\" line\n",
				fname, lineno, 0 );

			return( 1 );
		}

		LUTIL_SLASHPATH( cargv[1] );
		slurpd_pid_file = ch_strdup( cargv[1] );

	} else if ( strcasecmp( cargv[0], "replica-argsfile" ) == 0 ) {
		if ( cargc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"argsfile <file>\" line\n",
			    fname, lineno, 0 );

			return( 1 );
		}

		LUTIL_SLASHPATH( cargv[1] );
		slurpd_args_file = ch_strdup( cargv[1] );

		} else if ( strcasecmp( cargv[0], "replicationinterval" ) == 0 ) {
			int c;
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY, "%s: line %d: missing interval in "
					"\"replicationinterval <seconds>\" line\n",
					fname, lineno, 0 );
				return( 1 );
			}

			if ( lutil_atoi( &c, cargv[1] ) != 0 || c < 1 ) {
				Debug( LDAP_DEBUG_ANY, "%s: line %d: invalid interval "
					"(%d) in \"replicationinterval <seconds>\" line\n",
					fname, lineno, c );

				return( 1 );
			}

			sglob->no_work_interval = c;
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
    char	*line
)
{
    char *	token;

    cargc = 0;
    for ( token = strtok_quote( line, " \t" ); token != NULL;
	token = strtok_quote( NULL, " \t" ) )
    {
        if ( cargc == cargv_size - 1 ) {
	    char **tmp;
            tmp = ch_realloc( cargv, (cargv_size + ARGS_STEP) *
                               sizeof(*cargv) );
	    if (tmp == NULL) {
		cargc = 0;
		return;
	    }
	    cargv = tmp;
            cargv_size += ARGS_STEP;
        }

	cargv[cargc++] = token;
    }
    cargv[cargc] = NULL;
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
slurpd_getline(
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
		if( p > buf && p[-1] == '\r' ) --p;       
		*p = '\0';
	}
	lineno++;
	if ( ! isspace( (unsigned char) buf[0] ) ) {
	    return( line );
	}

	/* change leading whitespace to space */
	buf[0] = ' ';

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
    LDAPURLDesc *ludp;

    for ( i = 1; i < cargc; i++ ) {
	if ( !strncasecmp( cargv[ i ], HOSTSTR, sizeof( HOSTSTR ) - 1 ) ) {
		if ( gots & GOT_HOST ) {
			fprintf( stderr, "Error: Malformed \"replica\" line in slapd config " );
			fprintf( stderr, "file, too many host or uri names specified, line %d\n",
				lineno );
			return -1;
		}	
	    val = cargv[ i ] + sizeof( HOSTSTR ); /* '\0' string terminator accounts for '=' */
	    if (( hp = strchr( val, ':' )) != NULL ) {
		*hp = '\0';
		hp++;
		if ( lutil_atoi( &ri->ri_port, hp ) != 0 ) {
		    fprintf( stderr, "unable to parse port \"%s\", line %d\n",
			    hp, lineno );
		    return -1;
		}
	    }
	    if ( ri->ri_port <= 0 ) {
		ri->ri_port = LDAP_PORT;
	    }
	    ri->ri_hostname = strdup( val );
	    gots |= GOT_HOST;
	} else if ( !strncasecmp( cargv[ i ], URISTR, sizeof( URISTR ) - 1 ) ) {
		if ( gots & GOT_HOST ) {
			fprintf( stderr, "Error: Malformed \"replica\" line in slapd config " );
			fprintf( stderr, "file, too many host or uri names specified, line %d\n",
				lineno );
			return -1;
		}		
		if ( ldap_url_parse( cargv[ i ] + sizeof( URISTR ), &ludp ) != LDAP_SUCCESS ) {
			fprintf( stderr, "Error: Malformed \"replica\" line in slapd config " );
			fprintf( stderr, "file, bad uri format specified, line %d\n",
				lineno );
			return -1;
		}
		if (ludp->lud_host == NULL) {
			fprintf( stderr, "Error: Malformed \"replica\" line in slapd config " );
			fprintf( stderr, "file, missing uri hostname, line %d\n",
				lineno );
			return -1;
		}
		ri->ri_hostname = strdup ( ludp->lud_host );
		ri->ri_port = ludp->lud_port;
		ri->ri_uri = strdup ( cargv[ i ] + sizeof( URISTR ) );		
		ldap_free_urldesc( ludp );				
	    gots |= GOT_HOST;
	} else if ( !strncasecmp( cargv[ i ], 
			ATTRSTR, sizeof( ATTRSTR ) - 1 ) ) {
	    /* ignore it */ ;
	} else if ( !strncasecmp( cargv[ i ], 
			SUFFIXSTR, sizeof( SUFFIXSTR ) - 1 ) ) {
	    /* ignore it */ ;
	} else if ( !strncasecmp( cargv[i], STARTTLSSTR, sizeof(STARTTLSSTR)-1 )) {
	    val = cargv[ i ] + sizeof( STARTTLSSTR );
		if( !strcasecmp( val, CRITICALSTR ) ) {
			ri->ri_tls = TLS_CRITICAL;
		} else {
			ri->ri_tls = TLS_ON;
		}
	} else if ( !strncasecmp( cargv[ i ], TLSSTR, sizeof( TLSSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( TLSSTR );
		if( !strcasecmp( val, CRITICALSTR ) ) {
			ri->ri_tls = TLS_CRITICAL;
		} else {
			ri->ri_tls = TLS_ON;
		}
	} else if ( !strncasecmp( cargv[ i ],
			BINDDNSTR, sizeof( BINDDNSTR ) - 1 ) ) { 
	    val = cargv[ i ] + sizeof( BINDDNSTR );
	    ri->ri_bind_dn = strdup( val );
	    gots |= GOT_DN;
	} else if ( !strncasecmp( cargv[ i ], BINDMETHSTR,
		sizeof( BINDMETHSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( BINDMETHSTR );
	    if ( !strcasecmp( val, KERBEROSSTR )) {
	    fprintf( stderr, "Error: a bind method of \"kerberos\" was\n" );
	    fprintf( stderr, "specified in the slapd configuration file.\n" );
	    fprintf( stderr, "slurpd no longer supports Kerberos.\n" );
	    exit( EXIT_FAILURE );
	    } else if ( !strcasecmp( val, SIMPLESTR )) {
		ri->ri_bind_method = LDAP_AUTH_SIMPLE;
		gots |= GOT_METHOD;
	    } else if ( !strcasecmp( val, SASLSTR )) {
		ri->ri_bind_method = LDAP_AUTH_SASL;
		gots |= GOT_METHOD;
	    } else {
		ri->ri_bind_method = -1;
	    }
	} else if ( !strncasecmp( cargv[ i ], 
			SASLMECHSTR, sizeof( SASLMECHSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( SASLMECHSTR );
	    gots |= GOT_MECH;
	    ri->ri_saslmech = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			CREDSTR, sizeof( CREDSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( CREDSTR );
	    ri->ri_password = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			SECPROPSSTR, sizeof( SECPROPSSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( SECPROPSSTR );
	    ri->ri_secprops = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			REALMSTR, sizeof( REALMSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( REALMSTR );
	    ri->ri_realm = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			AUTHCSTR, sizeof( AUTHCSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( AUTHCSTR );
	    ri->ri_authcId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			OLDAUTHCSTR, sizeof( OLDAUTHCSTR ) - 1 ) ) {
	    /* Old authcID is provided for some backwards compatibility */
	    val = cargv[ i ] + sizeof( OLDAUTHCSTR );
	    ri->ri_authcId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			AUTHZSTR, sizeof( AUTHZSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( AUTHZSTR );
	    ri->ri_authzId = strdup( val );
	} else if ( !strncasecmp( cargv[ i ], 
			SRVTABSTR, sizeof( SRVTABSTR ) - 1 ) ) {
	    val = cargv[ i ] + sizeof( SRVTABSTR );
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
    
	if ( ri->ri_bind_method == LDAP_AUTH_SASL) {
		if ((gots & GOT_MECH) == 0) {
			fprintf( stderr, "Error: \"replica\" line needs SASLmech flag in " );
			fprintf( stderr, "slapd config file, line %d\n", lineno );
			return -1;
		}
	} else if ( gots != GOT_ALL ) {
		fprintf( stderr, "Error: Malformed \"replica\" line in slapd " );
		fprintf( stderr, "config file, line %d\n", lineno );
		return -1;
	}
    return 0;
}


#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>
#include <ldif.h>

#define DEFSEP		"="


static void
usage( char *s )
{
    fprintf( stderr, "usage: %s [options] filter [attributes...]\nwhere:\n", s );
    fprintf( stderr, "    filter\tRFC-1558 compliant LDAP search filter\n" );
    fprintf( stderr, "    attributes\twhitespace-separated list of attributes to retrieve\n" );
    fprintf( stderr, "\t\t*          -- all user attributes\n" );
    fprintf( stderr, "\t\tempty list -- all non-operational attributes\n" );
    fprintf( stderr, "\t\t1.1        -- no attributes\n" );
    fprintf( stderr, "options:\n" );
    fprintf( stderr, "    -n\t\tshow what would be done but don't actually search\n" );
    fprintf( stderr, "    -v\t\trun in verbose mode (diagnostics to standard output)\n" );
    fprintf( stderr, "    -t\t\twrite values to files in /tmp\n" );
    fprintf( stderr, "    -u\t\tinclude User Friendly entry names in the output\n" );
    fprintf( stderr, "    -A\t\tretrieve attribute names only (no values)\n" );
    fprintf( stderr, "    -B\t\tdo not suppress printing of non-ASCII values\n" );
    fprintf( stderr, "    -L\t\tprint entries in LDIF format (-B is implied)\n" );
    fprintf( stderr, "    -M\t\tenable Manage DSA IT control (-MM implies critical)\n" );
    fprintf( stderr, "    -R\t\tdo not automatically follow referrals\n" );
    fprintf( stderr, "    -d level\tset LDAP debugging level to `level'\n" );
    fprintf( stderr, "    -F sep\tprint `sep' instead of `=' between attribute names and values\n" );
    fprintf( stderr, "    -S attr\tsort the results by attribute `attr'\n" );
    fprintf( stderr, "    -f file\tperform sequence of searches listed in `file'\n" );
    fprintf( stderr, "    -b basedn\tbase dn for search\n" );
    fprintf( stderr, "    -s scope\tone of base, one, or sub (search scope)\n" );
    fprintf( stderr, "    -a deref\tone of never, always, search, or find (alias dereferencing)\n" );
    fprintf( stderr, "    -l time lim\ttime limit (in seconds) for search\n" );
    fprintf( stderr, "    -z size lim\tsize limit (in entries) for search\n" );
    fprintf( stderr, "    -D binddn\tbind dn\n" );
    fprintf( stderr, "    -w passwd\tbind passwd (for simple authentication)\n" );
    fprintf( stderr, "    -W\t\tprompt for bind passwd\n" );
#ifdef HAVE_KERBEROS
    fprintf( stderr, "    -k\t\tuse Kerberos instead of Simple Password authentication\n" );
#endif
    fprintf( stderr, "    -h host\tldap server\n" );
    fprintf( stderr, "    -p port\tport on ldap server\n" );
    fprintf( stderr, "    -P version\tprocotol version (2 or 3)\n" );
    exit( EXIT_FAILURE );
}

static void print_entry LDAP_P((
    LDAP	*ld,
    LDAPMessage	*entry,
    int		attrsonly));

static int write_ldif_value LDAP_P((
	char *type,
	char *value,
	unsigned long vallen ));

static int dosearch LDAP_P((
	LDAP	*ld,
    char	*base,
    int		scope,
    char	**attrs,
    int		attrsonly,
    char	*filtpatt,
    char	*value));

static char	*binddn = NULL;
static char	*passwd = NULL;
static char	*base = NULL;
static char	*ldaphost = NULL;
static int	ldapport = 0;
static char	*sep = DEFSEP;
static char	*sortattr = NULL;
static int	skipsortattr = 0;
static int	verbose, not, includeufn, allow_binary, vals2tmp, ldif;

int
main( int argc, char **argv )
{
    char		*infile, *filtpattern, **attrs, line[ BUFSIZ ];
    FILE		*fp;
    int			rc, i, first, scope, deref, attrsonly, manageDSAit;
    int			referrals, timelimit, sizelimit, debug;
	int		authmethod, version, want_bindpw;
    LDAP		*ld;

    infile = NULL;
    debug = verbose = allow_binary = not = vals2tmp =
	    attrsonly = manageDSAit = ldif = want_bindpw = 0;

	deref = referrals = sizelimit = timelimit = version = -1;

	scope = LDAP_SCOPE_SUBTREE;
    authmethod = LDAP_AUTH_SIMPLE;

    while (( i = getopt( argc, argv, "WKknuvtMRABLD:s:f:h:b:d:P:p:F:a:w:l:z:S:")) != EOF ) {
	switch( i ) {
	case 'n':	/* do Not do any searches */
	    ++not;
	    break;
	case 'v':	/* verbose mode */
	    ++verbose;
	    break;
	case 'd':
	    debug |= atoi( optarg );
	    break;
	case 'k':	/* use kerberos bind */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
	    break;
	case 'K':	/* use kerberos bind, 1st part only */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
	    break;
	case 'u':	/* include UFN */
	    ++includeufn;
	    break;
	case 't':	/* write attribute values to /tmp files */
	    ++vals2tmp;
	    break;
	case 'M':
		/* enable Manage DSA IT */
		manageDSAit++;
		break;
	case 'R':	/* don't automatically chase referrals */
		referrals = (int) LDAP_OPT_OFF;
	    break;
	case 'A':	/* retrieve attribute names only -- no values */
	    ++attrsonly;
	    break;
	case 'L':	/* print entries in LDIF format */
	    ++ldif;
	    /* fall through -- always allow binary when outputting LDIF */
	case 'B':	/* allow binary values to be printed */
	    ++allow_binary;
	    break;
	case 's':	/* search scope */
	    if ( strcasecmp( optarg, "base" ) == 0 ) {
		scope = LDAP_SCOPE_BASE;
	    } else if ( strcasecmp( optarg, "one" ) == 0 ) {
		scope = LDAP_SCOPE_ONELEVEL;
	    } else if ( strcasecmp( optarg, "sub" ) == 0 ) {
		scope = LDAP_SCOPE_SUBTREE;
	    } else {
		fprintf( stderr, "scope should be base, one, or sub\n" );
		usage( argv[ 0 ] );
	    }
	    break;

	case 'a':	/* set alias deref option */
	    if ( strcasecmp( optarg, "never" ) == 0 ) {
		deref = LDAP_DEREF_NEVER;
	    } else if ( strcasecmp( optarg, "search" ) == 0 ) {
		deref = LDAP_DEREF_SEARCHING;
	    } else if ( strcasecmp( optarg, "find" ) == 0 ) {
		deref = LDAP_DEREF_FINDING;
	    } else if ( strcasecmp( optarg, "always" ) == 0 ) {
		deref = LDAP_DEREF_ALWAYS;
	    } else {
		fprintf( stderr, "alias deref should be never, search, find, or always\n" );
		usage( argv[ 0 ] );
	    }
	    break;
	    
	case 'F':	/* field separator */
	    sep = strdup( optarg );
	    break;
	case 'f':	/* input file */
	    infile = strdup( optarg );
	    break;
	case 'h':	/* ldap host */
	    ldaphost = strdup( optarg );
	    break;
	case 'b':	/* searchbase */
	    base = strdup( optarg );
	    break;
	case 'D':	/* bind DN */
	    binddn = strdup( optarg );
	    break;
	case 'p':	/* ldap port */
	    ldapport = atoi( optarg );
	    break;
	case 'w':	/* bind password */
	    passwd = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
	    break;
	case 'l':	/* time limit */
	    timelimit = atoi( optarg );
	    break;
	case 'z':	/* size limit */
	    sizelimit = atoi( optarg );
	    break;
	case 'S':	/* sort attribute */
	    sortattr = strdup( optarg );
	    break;
	case 'W':
		want_bindpw++;
		break;
	case 'P':
		switch( atoi( optarg ) )
		{
		case 2:
			version = LDAP_VERSION2;
			break;
		case 3:
			version = LDAP_VERSION3;
			break;
		default:
			fprintf( stderr, "protocol version should be 2 or 3\n" );
			usage( argv[0] );
		}
		break;
	default:
	    usage( argv[0] );
	}
    }

    if ( argc - optind < 1 ) {
	usage( argv[ 0 ] );
    }
    filtpattern = strdup( argv[ optind ] );
    if ( argv[ optind + 1 ] == NULL ) {
	attrs = NULL;
    } else if ( sortattr == NULL || *sortattr == '\0' ) {
        attrs = &argv[ optind + 1 ];
    } else {
	for ( i = optind + 1; i < argc; i++ ) {
	    if ( strcasecmp( argv[ i ], sortattr ) == 0 ) {
		break;
	    }
	}
	if ( i == argc ) {
		skipsortattr = 1;
		argv[ optind ] = sortattr;
	} else {
		optind++;
	}
        attrs = &argv[ optind ];
    }

    if ( infile != NULL ) {
	if ( infile[0] == '-' && infile[1] == '\0' ) {
	    fp = stdin;
	} else if (( fp = fopen( infile, "r" )) == NULL ) {
	    perror( infile );
	    return( EXIT_FAILURE );
	}
    }

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug ) != LBER_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
		ldif_debug = debug;
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

    if ( verbose ) {
	fprintf( stderr, "ldap_init( %s, %d )\n",
		(ldaphost != NULL) ? ldaphost : "<DEFAULT>",
		ldapport );
    }

    if (( ld = ldap_init( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_init" );
	return( EXIT_FAILURE );
    }

	if (deref != -1 &&
		ldap_set_option( ld, LDAP_OPT_DEREF, (void *) &deref ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_DEREF %d\n", deref );
	}
	if (timelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_TIMELIMIT, (void *) &timelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_TIMELIMIT %d\n", timelimit );
	}
	if (sizelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_SIZELIMIT, (void *) &sizelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_SIZELIMIT %d\n", sizelimit );
	}
	if (referrals != -1 &&
		ldap_set_option( ld, LDAP_OPT_REFERRALS,
				 (referrals ? LDAP_OPT_ON : LDAP_OPT_OFF) ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
	}

	if (version != -1 &&
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

    if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_bind" );
	return( EXIT_FAILURE );
    }

    if ( verbose ) {
	fprintf( stderr, "filter pattern: %s\nreturning: ", filtpattern );
	if ( attrs == NULL ) {
	    printf( "ALL" );
	} else {
	    for ( i = 0; attrs[ i ] != NULL; ++i ) {
		fprintf( stderr, "%s ", attrs[ i ] );
	    }
	}
	fprintf( stderr, "\n" );
    }

	if ( manageDSAit ) {
		int err;
		LDAPControl c;
		LDAPControl *ctrls[2];
		ctrls[0] = &c;
		ctrls[1] = NULL;

		c.ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		c.ldctl_value.bv_val = NULL;
		c.ldctl_value.bv_len = 0;
		c.ldctl_iscritical = manageDSAit > 1;

		err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, &ctrls );

		if( err != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set Manage DSA IT Control\n" );
			if( c.ldctl_iscritical ) {
				exit( EXIT_FAILURE );
			}
		}
	}

    if ( infile == NULL ) {
	rc = dosearch( ld, base, scope, attrs, attrsonly, filtpattern, "" );
    } else {
	rc = 0;
	first = 1;
	while ( rc == 0 && fgets( line, sizeof( line ), fp ) != NULL ) {
	    line[ strlen( line ) - 1 ] = '\0';
	    if ( !first ) {
		putchar( '\n' );
	    } else {
		first = 0;
	    }
	    rc = dosearch( ld, base, scope, attrs, attrsonly, filtpattern,
		    line );
	}
	if ( fp != stdin ) {
	    fclose( fp );
	}
    }

    ldap_unbind( ld );


	return( rc );
}


static int dosearch(
	LDAP	*ld,
    char	*base,
    int		scope,
    char	**attrs,
    int		attrsonly,
    char	*filtpatt,
    char	*value)
{
    char		filter[ BUFSIZ ];
    int			rc, first, matches;
    LDAPMessage		*res, *e;

    sprintf( filter, filtpatt, value );

    if ( verbose ) {
	fprintf( stderr, "filter is: (%s)\n", filter );
    }

    if ( not ) {
	return( LDAP_SUCCESS );
    }

    if ( ldap_search( ld, base, scope, filter, attrs, attrsonly ) == -1 ) {
		int ld_errno;
		ldap_perror( ld, "ldap_search" );

		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
		return( ld_errno );
    }

    matches = 0;
    first = 1;
    res = NULL;
    while ( (rc = ldap_result( ld, LDAP_RES_ANY, sortattr ? 1 : 0, NULL, &res ))
	    == LDAP_RES_SEARCH_ENTRY ) {
	matches++;
	e = ldap_first_entry( ld, res );
	if ( !first ) {
	    putchar( '\n' );
	} else {
	    first = 0;
	}
	print_entry( ld, e, attrsonly );
	ldap_msgfree( res );
	res = NULL;
    }
    if ( rc == -1 ) {
	ldap_perror( ld, "ldap_result" );
	return( rc );
    }
    if (( rc = ldap_result2error( ld, res, 0 )) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search" );
    }
    if ( sortattr != NULL ) {
	    (void) ldap_sort_entries( ld, &res,
		    ( *sortattr == '\0' ) ? NULL : sortattr, strcasecmp );
	    matches = 0;
	    first = 1;
	    for ( e = ldap_first_entry( ld, res ); e != NULL;
		    e = ldap_next_entry( ld, e ) ) {
		matches++;
		if ( !first ) {
		    putchar( '\n' );
		} else {
		    first = 0;
		}
		print_entry( ld, e, attrsonly );
	    }
    }

    if ( verbose ) {
        printf( "%d matches\n", matches );
    }

    ldap_msgfree( res );
    return( rc );
}


void print_entry(
    LDAP	*ld,
    LDAPMessage	*entry,
    int		attrsonly)
{
    char		*a, *dn, *ufn, tmpfname[ 64 ];
    int			i, j, notascii;
    BerElement		*ber = NULL;
    struct berval	**bvals;
    FILE		*tmpfp;

    dn = ldap_get_dn( ld, entry );
    if ( ldif ) {
	write_ldif_value( "dn", dn, strlen( dn ));
    } else {
	printf( "%s\n", dn );
    }
    if ( includeufn ) {
	ufn = ldap_dn2ufn( dn );
	if ( ldif ) {
	    write_ldif_value( "ufn", ufn, strlen( ufn ));
	} else {
	    printf( "%s\n", ufn );
	}
	ldap_memfree( ufn );
    }
    ldap_memfree( dn );

    for ( a = ldap_first_attribute( ld, entry, &ber ); a != NULL;
	    a = ldap_next_attribute( ld, entry, ber ) ) {
	if ( skipsortattr && strcasecmp( a, sortattr ) == 0 ) {
	    continue;
	}
	if ( attrsonly ) {
	    if ( ldif ) {
		write_ldif_value( a, "", 0 );
	    } else {
		printf( "%s\n", a );
	    }
	} else if (( bvals = ldap_get_values_len( ld, entry, a )) != NULL ) {
	    for ( i = 0; bvals[i] != NULL; i++ ) {
		if ( vals2tmp ) {
		    sprintf( tmpfname, "/tmp/ldapsearch-%s-XXXXXX", a );
		    tmpfp = NULL;

		    if ( mktemp( tmpfname ) == NULL ) {
			perror( tmpfname );
		    } else if (( tmpfp = fopen( tmpfname, "w")) == NULL ) {
			perror( tmpfname );
		    } else if ( fwrite( bvals[ i ]->bv_val,
			    bvals[ i ]->bv_len, 1, tmpfp ) == 0 ) {
			perror( tmpfname );
		    } else if ( ldif ) {
			write_ldif_value( a, tmpfname, strlen( tmpfname ));
		    } else {
			printf( "%s%s%s\n", a, sep, tmpfname );
		    }

		    if ( tmpfp != NULL ) {
			fclose( tmpfp );
		    }
		} else {
		    notascii = 0;
		    if ( !allow_binary ) {
			for ( j = 0; (unsigned long) j < bvals[ i ]->bv_len; ++j ) {
			    if ( !isascii( bvals[ i ]->bv_val[ j ] )) {
				notascii = 1;
				break;
			    }
			}
		    }

		    if ( ldif ) {
			write_ldif_value( a, bvals[ i ]->bv_val,
				bvals[ i ]->bv_len );
		    } else {
			printf( "%s%s%s\n", a, sep,
				notascii ? "NOT ASCII" : bvals[ i ]->bv_val );
		    }
		}
	    }
	    ber_bvecfree( bvals );
	}
    }

	if( ber != NULL ) {
		ber_free( ber, 0 );
	}
}


int
write_ldif_value( char *type, char *value, unsigned long vallen )
{
    char	*ldif;

    if (( ldif = ldif_type_and_value( type, value, (int)vallen )) == NULL ) {
	return( -1 );
    }

    fputs( ldif, stdout );
    ber_memfree( ldif );

    return( 0 );
}

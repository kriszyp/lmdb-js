#include "portable.h"

#include <stdio.h>
#include <ctype.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <lber.h>
#include <ldap.h>
#include <ldif.h>

#include "ldapconfig.h"

#define DEFSEP		"="

#ifdef LDAP_DEBUG
extern int ldap_debug, lber_debug;
#endif /* LDAP_DEBUG */


static void usage( s )
char	*s;
{
    fprintf( stderr, "usage: %s [options] filter [attributes...]\nwhere:\n", s );
    fprintf( stderr, "    filter\tRFC-1558 compliant LDAP search filter\n" );
    fprintf( stderr, "    attributes\twhitespace-separated list of attributes to retrieve\n" );
    fprintf( stderr, "\t\t(if no attribute list is given, all are retrieved)\n" );
    fprintf( stderr, "options:\n" );
    fprintf( stderr, "    -n\t\tshow what would be done but don't actually search\n" );
    fprintf( stderr, "    -v\t\trun in verbose mode (diagnostics to standard output)\n" );
    fprintf( stderr, "    -t\t\twrite values to files in /tmp\n" );
    fprintf( stderr, "    -u\t\tinclude User Friendly entry names in the output\n" );
    fprintf( stderr, "    -A\t\tretrieve attribute names only (no values)\n" );
    fprintf( stderr, "    -B\t\tdo not suppress printing of non-ASCII values\n" );
    fprintf( stderr, "    -L\t\tprint entries in LDIF format (-B is implied)\n" );
#ifdef LDAP_REFERRALS
    fprintf( stderr, "    -R\t\tdo not automatically follow referrals\n" );
#endif /* LDAP_REFERRALS */
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
#ifdef KERBEROS
    fprintf( stderr, "    -k\t\tuse Kerberos instead of Simple Password authentication\n" );
#endif
    fprintf( stderr, "    -h host\tldap server\n" );
    fprintf( stderr, "    -p port\tport on ldap server\n" );
    exit( 1 );
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

static char	*binddn = LDAPSEARCH_BINDDN;
static char	*passwd = LDAPSEARCH_BIND_CRED;
static char	*base = LDAPSEARCH_BASE;
static char	*ldaphost = LDAPHOST;
static int	ldapport = LDAP_PORT;
static char	*sep = DEFSEP;
static char	*sortattr = NULL;
static int	skipsortattr = 0;
static int	verbose, not, includeufn, allow_binary, vals2tmp, ldif;

main( argc, argv )
int	argc;
char	**argv;
{
    char		*infile, *filtpattern, **attrs, line[ BUFSIZ ];
    FILE		*fp;
    int			rc, i, first, scope, kerberos, deref, attrsonly;
    int			ldap_options, timelimit, sizelimit, authmethod;
    LDAP		*ld;
    extern char		*optarg;
    extern int		optind;

    infile = NULL;
    deref = verbose = allow_binary = not = kerberos = vals2tmp =
	    attrsonly = ldif = 0;
#ifdef LDAP_REFERRALS
    ldap_options = LDAP_OPT_REFERRALS;
#else /* LDAP_REFERRALS */
    ldap_options = 0;
#endif /* LDAP_REFERRALS */
    sizelimit = timelimit = 0;
    scope = LDAP_SCOPE_SUBTREE;

    while (( i = getopt( argc, argv,
#ifdef KERBEROS
	    "KknuvtRABLD:s:f:h:b:d:p:F:a:w:l:z:S:"
#else
	    "nuvtRABLD:s:f:h:b:d:p:F:a:w:l:z:S:"
#endif
	    )) != EOF ) {
	switch( i ) {
	case 'n':	/* do Not do any searches */
	    ++not;
	    break;
	case 'v':	/* verbose mode */
	    ++verbose;
	    break;
	case 'd':
#ifdef LDAP_DEBUG
	    ldap_debug = lber_debug = atoi( optarg );	/* */
#else /* LDAP_DEBUG */
	    fprintf( stderr, "compile with -DLDAP_DEBUG for debugging\n" );
#endif /* LDAP_DEBUG */
	    break;
#ifdef KERBEROS
	case 'k':	/* use kerberos bind */
	    kerberos = 2;
	    break;
	case 'K':	/* use kerberos bind, 1st part only */
	    kerberos = 1;
	    break;
#endif
	case 'u':	/* include UFN */
	    ++includeufn;
	    break;
	case 't':	/* write attribute values to /tmp files */
	    ++vals2tmp;
	    break;
	case 'R':	/* don't automatically chase referrals */
#ifdef LDAP_REFERRALS
	    ldap_options &= ~LDAP_OPT_REFERRALS;
#else /* LDAP_REFERRALS */
	    fprintf( stderr,
		    "compile with -DLDAP_REFERRALS for referral support\n" );
#endif /* LDAP_REFERRALS */
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
	    if ( strncasecmp( optarg, "base", 4 ) == 0 ) {
		scope = LDAP_SCOPE_BASE;
	    } else if ( strncasecmp( optarg, "one", 3 ) == 0 ) {
		scope = LDAP_SCOPE_ONELEVEL;
	    } else if ( strncasecmp( optarg, "sub", 3 ) == 0 ) {
		scope = LDAP_SCOPE_SUBTREE;
	    } else {
		fprintf( stderr, "scope should be base, one, or sub\n" );
		usage( argv[ 0 ] );
	    }
	    break;

	case 'a':	/* set alias deref option */
	    if ( strncasecmp( optarg, "never", 5 ) == 0 ) {
		deref = LDAP_DEREF_NEVER;
	    } else if ( strncasecmp( optarg, "search", 5 ) == 0 ) {
		deref = LDAP_DEREF_SEARCHING;
	    } else if ( strncasecmp( optarg, "find", 4 ) == 0 ) {
		deref = LDAP_DEREF_FINDING;
	    } else if ( strncasecmp( optarg, "always", 6 ) == 0 ) {
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
	    exit( 1 );
	}
    }

    if ( verbose ) {
	printf( "ldap_open( %s, %d )\n", ldaphost, ldapport );
    }

    if (( ld = ldap_open( ldaphost, ldapport )) == NULL ) {
	perror( ldaphost );
	exit( 1 );
    }

    ld->ld_deref = deref;
    ld->ld_timelimit = timelimit;
    ld->ld_sizelimit = sizelimit;
    ld->ld_options = ldap_options;

    if ( !kerberos ) {
	authmethod = LDAP_AUTH_SIMPLE;
    } else if ( kerberos == 1 ) {
	authmethod = LDAP_AUTH_KRBV41;
    } else {
	authmethod =  LDAP_AUTH_KRBV4;
    }
    if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_bind" );
	exit( 1 );
    }

    if ( verbose ) {
	printf( "filter pattern: %s\nreturning: ", filtpattern );
	if ( attrs == NULL ) {
	    printf( "ALL" );
	} else {
	    for ( i = 0; attrs[ i ] != NULL; ++i ) {
		printf( "%s ", attrs[ i ] );
	    }
	}
	putchar( '\n' );
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
    exit( rc );
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
	printf( "filter is: (%s)\n", filter );
    }

    if ( not ) {
	return( LDAP_SUCCESS );
    }

    if ( ldap_search( ld, base, scope, filter, attrs, attrsonly ) == -1 ) {
	ldap_perror( ld, "ldap_search" );
	return( ld->ld_errno );
    }

    matches = 0;
    first = 1;
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
    }
    if ( rc == -1 ) {
	ldap_perror( ld, "ldap_result" );
	return( rc );
    }
    if (( rc = ldap_result2error( ld, res, 0 )) != LDAP_SUCCESS ) {
        ldap_perror( ld, "ldap_search" );
    }
    if ( sortattr != NULL ) {
	    extern int	strcasecmp();

	    (void) ldap_sort_entries( ld, &res,
		    ( *sortattr == '\0' ) ? NULL : sortattr, strcasecmp );
	    matches = 0;
	    first = 1;
	    for ( e = ldap_first_entry( ld, res ); e != NULLMSG;
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
    BerElement		*ber;
    struct berval	**bvals;
    FILE		*tmpfp;
    extern char		*mktemp();

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
	free( ufn );
    }
    free( dn );

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
}


int
write_ldif_value( char *type, char *value, unsigned long vallen )
{
    char	*ldif;

    if (( ldif = ldif_type_and_value( type, value, (int)vallen )) == NULL ) {
	return( -1 );
    }

    fputs( ldif, stdout );
    free( ldif );

    return( 0 );
}

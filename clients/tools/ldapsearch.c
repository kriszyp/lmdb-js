/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/errno.h>
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldif.h"
#include "ldap_defaults.h"

#define DEFSEP		"="

static void
usage( const char *s )
{
	fprintf( stderr,
"usage: %s [options] filter [attributes...]\nwhere:\n"
"	filter\tRFC-1558 compliant LDAP search filter\n"
"	attributes\twhitespace-separated list of attributes to retrieve\n"
"\t\t1.1		-- no attributes\n"
"\t\t*		  -- all user attributes\n"
"\t\t+		  -- all operational attributes\n"
"\t\tempty list -- all non-operational attributes\n"
"options:\n"
"	-a deref\tone of `never', `always', `search', or `find' (alias\n"
"		\tdereferencing)\n"
"	-A\t\tretrieve attribute names only (no values)\n"
"	-b basedn\tbase dn for search\n"
"	-B\t\tdo not suppress printing of binary values\n"
"	-d level\tset LDAP debugging level to `level'\n"
"	-D binddn\tbind DN\n"
"	-E\t\trequest SASL privacy (-EE to make it critical)\n"
"	-f file\t\tperform sequence of searches listed in `file'\n"
"	-F sep\t\tprint `sep' instead of `=' between attribute names and\n"
"		\tvalues\n"
"	-h host\t\tLDAP server\n"
"	-I\t\trequest SASL integrity checking (-II to make it\n"
"		\tcritical)\n"
"	-k\t\tuse Kerberos authentication\n"
"	-K\t\tlike -k, but do only step 1 of the Kerberos bind\n"
"	-l limit\ttime limit (in seconds) for search\n"
"	-L\t\tprint entries in LDIF format (implies -B)\n"
"	-LL\t\tprint entries in LDIF format without comments\n"
"	-LLL\t\tprint entries in LDIF format without comments and\n"
"		\tversion\n"
"	-M\t\tenable Manage DSA IT control (-MM to make critical)\n"
"	-n\t\tshow what would be done but don't actually search\n"
"	-p port\t\tport on LDAP server\n"
"	-P version\tprocotol version (2 or 3)\n"
"	-R\t\tdo not automatically follow referrals\n"
"	-s scope\tone of base, one, or sub (search scope)\n"
"	-S attr\t\tsort the results by attribute `attr'\n"
"	-t\t\twrite binary values to files in TMPDIR\n"
"	-tt\t\twrite all values to files in TMPDIR\n"
"	-T path\t\twrite files to directory specified by path (default:\n"
"		\t\"/tmp\")\n"
"	-u\t\tinclude User Friendly entry names in the output\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\trun in verbose mode (diagnostics to standard output)\n"
"	-V prefix\tURL prefix for files (default: \"file://tmp/\")\n"
"	-w passwd\tbind passwd (for simple authentication)\n"
"	-W\t\tprompt for bind passwd\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-z limit\tsize limit (in entries) for search\n"
"	-Z\t\trequest the use of TLS (-ZZ to make it critical)\n"
,		s );

	exit( EXIT_FAILURE );
}

static void print_entry LDAP_P((
	LDAP	*ld,
	LDAPMessage	*entry,
	int		attrsonly));

static int write_ldif LDAP_P((
	int type,
	char *name,
	char *value,
	ber_len_t vallen ));

static int dosearch LDAP_P((
	LDAP	*ld,
	char	*base,
	int		scope,
	char	**attrs,
	int		attrsonly,
	char	*filtpatt,
	char	*value));

#define TMPDIR "/tmp"
#define URLPRE "file:/tmp/"

static char *tmpdir = NULL;
static char *urlpre = NULL;

static char	*binddn = NULL;
static char	*passwd = NULL;
static char	*base = NULL;
static char	*ldaphost = NULL;
static int	ldapport = 0;
#ifdef HAVE_CYRUS_SASL
static char	*sasl_authc_id = NULL;
static char	*sasl_authz_id = NULL;
static char	*sasl_mech = NULL;
static int	sasl_integrity = 0;
static int	sasl_privacy = 0;
#endif
static int	use_tls = 0;
static char	*sep = DEFSEP;
static char	*sortattr = NULL;
static int	skipsortattr = 0;
static int	verbose, not, includeufn, binary, vals2tmp, ldif;

int
main( int argc, char **argv )
{
	char		*infile, *filtpattern, **attrs, line[ BUFSIZ ];
	FILE		*fp = NULL;
	int			rc, i, first, scope, deref, attrsonly, manageDSAit;
	int			referrals, timelimit, sizelimit, debug;
	int		authmethod, version, want_bindpw;
	LDAP		*ld;

	infile = NULL;
	debug = verbose = binary = not = vals2tmp =
		attrsonly = manageDSAit = ldif = want_bindpw = 0;

	deref = referrals = sizelimit = timelimit = version = -1;

	scope = LDAP_SCOPE_SUBTREE;
	authmethod = LDAP_AUTH_SIMPLE;

	while (( i = getopt( argc, argv,
		"Aa:Bb:D:d:EF:f:h:IKkLl:MnP:p:RS:s:T:tU:uV:vWw:X:Y:Zz:")) != EOF )
	{
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
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'K':	/* use kerberos bind, 1st part only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
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
		++binary;
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
		
	case 'T':	/* field separator */
		if( tmpdir ) free( tmpdir );
		tmpdir = strdup( optarg );
		break;
	case 'V':	/* field separator */
		if( urlpre ) free( urlpre );
		urlpre = strdup( optarg );
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
	case 'I':
#ifdef HAVE_CYRUS_SASL
		sasl_integrity++;
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'E':
#ifdef HAVE_CYRUS_SASL
		sasl_privacy++;
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Y':
#ifdef HAVE_CYRUS_SASL
		if ( strcasecmp( optarg, "any" ) && strcmp( optarg, "*" ) ) {
			sasl_mech = strdup( optarg );
		}
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
		sasl_authc_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'X':
#ifdef HAVE_CYRUS_SASL
		sasl_authz_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Z':
#ifdef HAVE_TLS
		use_tls++;
#else
		fprintf( stderr, "%s was not compiled with TLS support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	default:
		usage( argv[0] );
	}
	}

#ifdef LDAP_LDIF
	/* no alternative format */
	if( ldif < 1 ) ldif = 1;
#endif

	if ( ( authmethod == LDAP_AUTH_KRBV4 ) || ( authmethod ==
			LDAP_AUTH_KRBV41 ) ) {
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "Kerberos requires LDAPv2\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION2;
	}
	else if ( authmethod == LDAP_AUTH_SASL ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf( stderr, "SASL requires LDAPv3\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION3;
	}

	if( manageDSAit ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

	if( use_tls ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "Start TLS requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
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
			return EXIT_FAILURE;
		}
	}

	if( tmpdir == NULL
		&& (tmpdir = getenv("TMPDIR")) == NULL
		&& (tmpdir = getenv("TMP")) == NULL
		&& (tmpdir = getenv("TEMP")) == NULL )
	{
		tmpdir = "/tmp";
	}

	if( urlpre == NULL ) {
		urlpre = malloc( sizeof("file:///") + strlen(tmpdir) );

		if( urlpre == NULL ) {
			perror( "malloc" );
			return EXIT_FAILURE;
		}

		sprintf( urlpre, "file:///%s/",
			tmpdir[0] == '/' ? &tmpdir[1] : tmpdir );

		/* urlpre should be URLized.... */
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
		fprintf( stderr,
			(ldapport ? "ldap_init( %s, %d )\n" : "ldap_init( %s, <DEFAULT> )\n"),
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

	if ( use_tls && ldap_start_tls( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		if ( use_tls > 1 ) {
			ldap_perror( ld, "ldap_start_tls" );
			return( EXIT_FAILURE );
		}
	}

	if (want_bindpw) {
		passwd = getpass("Enter LDAP Password: ");
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		int	minssf = 0, maxssf = 0;

		if ( sasl_integrity > 0 )
			maxssf = 1;
		if ( sasl_integrity > 1 )
			minssf = 1;
		if ( sasl_privacy > 0 )
			maxssf = 100000; /* Something big value */
		if ( sasl_privacy > 1 )
			minssf = 56;
		
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MINSSF,
				(void *)&minssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MINSSF"
				"%d\n", minssf);
			return( EXIT_FAILURE );
		}
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MAXSSF,
				(void *)&maxssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MAXSSF"
				"%d\n", maxssf);
			return( EXIT_FAILURE );
		}
		
		if ( ldap_negotiated_sasl_bind_s( ld, binddn, sasl_authc_id,
				sasl_authz_id, sasl_mech, NULL, NULL, NULL )
					!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_bind" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
	}
	else {
		if ( ldap_bind_s( ld, binddn, passwd, authmethod )
				!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
			return( EXIT_FAILURE );
		}
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

	if ( verbose ) {
		fprintf( stderr, "filter%s: %s\nreturning: ",
			infile != NULL ? " pattern" : "",
			filtpattern );

		if ( attrs == NULL ) {
			fprintf( stderr, "ALL" );
		} else {
			for ( i = 0; attrs[ i ] != NULL; ++i ) {
				fprintf( stderr, "%s ", attrs[ i ] );
			}
		}
		fprintf( stderr, "\n" );
	}

	if ( ldif ) {
		if (ldif < 3 ) {
			printf( "version: 1\n\n");
		}

		if (ldif < 2 ) {
			printf( "#\n# filter%s: %s\n# returning: ",
				infile != NULL ? " pattern" : "",
				filtpattern );

			if ( attrs == NULL ) {
				printf( "ALL" );
			} else {
				for ( i = 0; attrs[ i ] != NULL; ++i ) {
					printf( "%s ", attrs[ i ] );
				}
			}
			printf( "\n#\n\n" );
		}
	}

	if ( infile == NULL ) {
		rc = dosearch( ld, base, scope, attrs, attrsonly, NULL, filtpattern );

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
			rc = dosearch( ld, base, scope, attrs, attrsonly,
				filtpattern, line );
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

	if( filtpatt != NULL ) {
		sprintf( filter, filtpatt, value );

		if ( verbose ) {
			fprintf( stderr, "filter is: (%s)\n", filter );
		}

		if( ldif == 1 ) {
			printf( "#\n# filter: %s\n#\n", filter );
		}

	} else {
		sprintf( filter, "%s", value );
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


static void
print_entry(
	LDAP	*ld,
	LDAPMessage	*entry,
	int		attrsonly)
{
	char		*a, *dn, *ufn;
	char	tmpfname[ 256 ];
	char	url[ 256 ];
	int			i;
	BerElement		*ber = NULL;
	struct berval	**bvals;
	FILE		*tmpfp;

	dn = ldap_get_dn( ld, entry );
	ufn = NULL;

	if ( ldif == 1 ) {
		ufn = ldap_dn2ufn( dn );
		write_ldif( LDIF_PUT_COMMENT, NULL, ufn, strlen( ufn ));
	}
	if ( ldif ) {
		write_ldif( LDIF_PUT_VALUE, "dn", dn, strlen( dn ));
	} else {
		printf( "%s\n", dn );
	}

	if ( includeufn ) {
		if( ufn == NULL ) {
			ufn = ldap_dn2ufn( dn );
		}
		if ( ldif ) {
			write_ldif( LDIF_PUT_VALUE, "ufn", ufn, strlen( ufn ));
		} else {
			printf( "%s\n", ufn );
		}
	}

	if( ufn != NULL ) ldap_memfree( ufn );
	ldap_memfree( dn );

	for ( a = ldap_first_attribute( ld, entry, &ber ); a != NULL;
		a = ldap_next_attribute( ld, entry, ber ) )
	{
		if ( skipsortattr && strcasecmp( a, sortattr ) == 0 ) {
			continue;
		}

		if ( attrsonly ) {
			if ( ldif ) {
				write_ldif( LDIF_PUT_NOVALUE, a, NULL, 0 );
			} else {
				printf( "%s\n", a );
			}

		} else if (( bvals = ldap_get_values_len( ld, entry, a )) != NULL ) {
			for ( i = 0; bvals[i] != NULL; i++ ) {
				if ( vals2tmp > 1 || ( vals2tmp
					&& ldif_is_not_printable( bvals[i]->bv_val, bvals[i]->bv_len ) ))
				{
					int tmpfd;
					/* write value to file */
					sprintf( tmpfname, "%s" LDAP_DIRSEP "ldapsearch-%s-XXXXXX",
						tmpdir, a );
					tmpfp = NULL;

					if ( mktemp( tmpfname ) == NULL ) {
						perror( tmpfname );
						continue;
					}

					if (( tmpfd = open( tmpfname, O_WRONLY|O_CREAT|O_EXCL, 0600 )) == -1 ) {
						perror( tmpfname );
						continue;
					}

					if (( tmpfp = fdopen( tmpfd, "w")) == NULL ) {
						perror( tmpfname );
						continue;
					}

					if ( fwrite( bvals[ i ]->bv_val,
						bvals[ i ]->bv_len, 1, tmpfp ) == 0 )
					{
						perror( tmpfname );
						fclose( tmpfp );
						continue;
					}

					fclose( tmpfp );

					sprintf( url, "%s%s", urlpre,
						&tmpfname[strlen(tmpdir) + sizeof(LDAP_DIRSEP) - 1] );

					if ( ldif ) {
						write_ldif( LDIF_PUT_URL, a, url, strlen( url ));
					} else {
						printf( "%s%s%s\n", a, sep, url );
					}


				} else {
					if ( ldif ) {
						write_ldif( LDIF_PUT_VALUE, a,
							bvals[ i ]->bv_val, bvals[ i ]->bv_len );

					} else {
						int notprint = !binary && !vals2tmp
							&& ldif_is_not_printable( bvals[i]->bv_val,
								bvals[i]->bv_len ); 
						printf( "%s%s", a, sep );
						puts( notprint ? "NOT PRINTABLE" : bvals[ i ]->bv_val );
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


static int
write_ldif( int type, char *name, char *value, ber_len_t vallen )
{
	char	*ldif;

	if (( ldif = ldif_put( type, name, value, vallen )) == NULL ) {
		return( -1 );
	}

	fputs( ldif, stdout );
	ber_memfree( ldif );

	return( 0 );
}

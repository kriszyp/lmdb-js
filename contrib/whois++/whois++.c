#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			W H O I S + +
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *	This is an experimental implementation of the proposed IETF
 *	WNILS WG update to the whois/nicname protocol (whois++).
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Adelaide. The name of the University may not
 * be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "whois++.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

static initialise();

main( argc, argv )
int	argc;
char	**argv;
{
	FILE			*tailorFile, *bannerFile;
	char			tailor[MAXPATHLEN];
	char			query[BUFSIZ], buffer[BUFSIZ];
	char			*s, *hostname, *remote;
	char			**info;
	int			i, printInfo = FALSE;
	extern char		*optarg;
	LDAP			*ld;
	LDAPMessage		*result, *entry;
	int			timelimit = DEFAULT_TIMELIMIT;
	struct hostent		*hp;
	static struct sockaddr	sa;
	struct sockaddr_in	*sin = (struct sockaddr_in *) (&sa);
	/* #### length should be socklen_t when we include portable.h #### */
	int			length = sizeof(sa);
	static char		options[] = "[-b searchbase] [-d debug ] \
[-h ldaphost ] [-i] [-l] [-s sizelimit] [-t timelimit] [-T tailorfile ] \
[-u user] [-v]";
	static char		*attributes[] =
					{ "businessCategory", "info", NULL };

	if ( (program = strrchr( argv[0], '/' )) == NULL )
		program = strdup( argv[0] );
	else
		program = strdup( program + 1 );

#if defined(LOG_DAEMON)
	openlog(program, LOG_PID, FACILITY );
#else
	openlog(program, LOG_PID );
#endif

	initialise();

	sprintf( tailor, "%s/%stailor", ETCDIR, program );
	if ( (tailorFile = fopen( tailor, "r" )) != NULL ) {
		readConfiguration( tailorFile );
		fclose( tailorFile );
	}

	while ( (i = getopt( argc, argv, "b:d:h:ils:t:T:u:v?" )) != EOF ) {
		switch ( i ) {
		case 'b':	/* search base */
			base = strdup( optarg );
			break;

		case 'd':	/* debug */
			debug = atoi( optarg );
			break;

		case 'h':	/* ldap host */
			ldaphost = strdup( optarg );
			break;

		case 'i':	/* print info attribute */
			printInfo = TRUE;
			break;

		case 'l':	/* enable logging via syslog */
			log = TRUE;
			break;

		case 's':	/* size limit */
			if ( ( maxHits = atoi( optarg ) ) < 1 ) {
				fprintf( stderr, "%s: Invalid maxhits value\n",
					program );
				syslog( LOG_ERR, "Invalid maxhits value" );
				exit( 1 );
			}
			maximumSize = maxHits;
			break;

		case 't':	/* time limit */
			timelimit = atoi( optarg );
			break;

		case 'T':	/* tailor file */
			if ( (tailorFile = fopen( optarg, "r" )) != NULL ) {
				readConfiguration( tailorFile );
				fclose( tailorFile );
			} else {
				perror( program );
				exit( 1 );
			}
			break;

		case 'u':	/* user to bind as */
			user = strdup( optarg );
			break;

		case 'v':	/* version */
			fprintf( stderr, "%s: %s %d.%s\n",
				program, RELEASE, REVISION, version() );
			exit( 0 );

		default:	/* usage message, don't "fail" if ? */
			fprintf( stderr, "usage: %s %s\n", program, options );
			exit( i != '?' );
		}
	}

	language = defaultLanguage;

	/*
	 * We can cope without knowing most things but we do need to know
	 * where to start looking!
	 */
	if ( base == NULL ) {
		syslog( LOG_ERR, "No base specified" );
		fprintf( stderr, "%s: No base specified.\n", program );
		exit( 1 );
	}

	if ( ! debug ) {
		if ( getpeername(0, &sa, &length) < 0) {
			perror( "getpeername" );
			exit( 1 );
		}
		if ( log ) {
			if ( ( hp = gethostbyaddr((char *) &sin->sin_addr,
				sizeof(sin->sin_addr), AF_INET) ) != 0 ) {
				hostname = strdup( hp->h_name );
				if ( ( hp = gethostbyname( hostname ) ) == 0 ) {
					free( hostname );
					hostname = strdup( inet_ntoa(sin->sin_addr) );
				}
			} else
				hostname = strdup( inet_ntoa(sin->sin_addr) );
#if defined(RFC931)
			remote = rfc931_name( sin );
#else
			remote = NULL;
#endif
			syslog( LOG_INFO, "Connection from %s%s%s [%s]",
				(remote)?remote:"", (remote)?"@":"",
				hostname, inet_ntoa(sin->sin_addr) );
		}
	}

	if ( (ld = ldap_init( ldaphost, LDAP_PORT )) == NULL ) {
		printFormatted( lineLength, TRUE, stdout,
			"Connection to LDAP port on %s has failed", ldaphost );
		syslog( LOG_ERR, "Initialization of LDAP session (%s)",
			ldaphost );
		exit( 1 );
	}
	ld->ld_timelimit = timelimit;
	ld->ld_sizelimit = maxHits;
	ld->ld_deref = LDAP_DEREF_FINDING;

	ldap_simple_bind_s( ld, user, password );
	switch ( ld->ld_errno ) {
	case LDAP_SUCCESS:
		break;

	default:
		printFormatted( lineLength, TRUE, stdout,
			"Bind to Directory failed, %s",
			ldap_err2string( ld->ld_errno ) );
		syslog( LOG_ERR, "Bind to Directory failed, %s",
			ldap_err2string( ld->ld_errno ) );
		exit( 1 );

	}

	ldap_search_s( ld, base, LDAP_SCOPE_BASE, "objectclass=*",
		attributes, 0, &result );
	if ( ld->ld_errno != LDAP_SUCCESS ) {
		printFormatted( lineLength, TRUE, stdout,
			"Read of entry \"%s\" failed, %s",
			base, ldap_err2string( ld->ld_errno ) );
		exit( 1 );
	}
	entry = ldap_first_entry( ld, result );
	organisation = ldap_dn2ufn( ldap_get_dn( ld, entry ) );
	category = ldap_get_values( ld, entry, "businessCategory" );

	printFormatted( lineLength, FALSE, stdout,
		"Whois++ Service at %s.", ldap_dn2ufn( base ) );
	printFormatted( lineLength, FALSE, stdout,
		"For more information about this service send the \"help\" command." );

	if ( printInfo && ( info = ldap_get_values( ld, entry, "info" ) ) != NULL ) {
		for ( i = 0; info[i] != NULL; i++ ) {
			printFormatted( lineLength, FALSE, stdout, "" );
			printFormatted( lineLength, TRUE, stdout,
				"%s", info[i] );
		}
		ldap_value_free( info );
	}
	if ( banner != NULL && ( bannerFile = fopen( banner, "r" ) ) != NULL ) {
		printFormatted( lineLength, FALSE, stdout, "" );
		while ( fgets( buffer, BUFSIZ, bannerFile ) != NULL ) {
			i = strlen( buffer );
			while ( i-- > 0 && ( buffer[i] == '\n' || buffer[i] == '\r' ) )
				buffer[i] = '\0';
			printFormatted( lineLength, TRUE, stdout, "%s", buffer );
		}
		fclose( bannerFile );
	}
	printFormatted( lineLength, FALSE, stdout, "" );

	do {
		*query = '\0';
		holdConnection = FALSE;
		switch ( parseCommand( query ) ) {
		case READ:
			/* No need to search, just read the entry given! */
			ldap_search_s( ld, query, LDAP_SCOPE_BASE,
				"objectclass=*", NULL, 0, &result );
			switch( ld->ld_errno ) {
			case LDAP_SUCCESS:
				break;
		
			case LDAP_NO_SUCH_OBJECT:
/**/				/* PROBABLY WANT SPECIAL PROCESSING HERE */

			default:
				printFormatted( lineLength, TRUE, stdout,
					"Read failed, %s",
					ldap_err2string( ld->ld_errno ) );
				return 1;

			}
			displayResult( ld, result, outputFormat );
			break;

		case SEARCH:
			if ( debug > 2 )
				fprintf( stderr, "LDAP Query %s\n", query );
			if ( log )
				syslog( LOG_INFO, "LDAP Query %s", query );

			ld->ld_sizelimit = maxHits;
			ldap_search_s( ld, base, LDAP_SCOPE_SUBTREE, query,
				NULL, 0, &result );
			switch ( ld->ld_errno ) {
			case LDAP_SUCCESS:
				break;

			case LDAP_SIZELIMIT_EXCEEDED:
				printFormatted( lineLength, TRUE, stdout,
					"Partial results only - a size limit \
was exceeded, only %d entries returned", ldap_count_entries( ld, result ) );
				break;

			case LDAP_TIMELIMIT_EXCEEDED:
				printFormatted( lineLength, TRUE, stdout,
					"Partial results only - a time limit \
was exceeded." );
				break;

			default:
				printFormatted( lineLength, TRUE, stdout,
					"Search failed, %s",
					ldap_err2string( ld->ld_errno ) );
				exit( 1 );

			}
			displayResult( ld, result, outputFormat );
			break;

		case HELP:
			needHelp( lowerCase( query ) );
			break;

		case DESCRIBE:
			displayDescribe( ld, base );
			break;

		case VERSION:
			printFormatted( lineLength, TRUE, stdout,
				"Whois++ Protocol version %s", PROTOCOL );
			printFormatted( lineLength, TRUE, stdout,
				"Program version %s %d.%s",
				RELEASE, REVISION, version() );
			printFormatted( lineLength, TRUE, stdout,
				"Default language is %s", defaultLanguage );
			printFormatted( lineLength, TRUE, stdout,
				"Built by %s", BUILD );
			break;

		case LIST:
			listTemplates( lowerCase( query ) );
			break;

		case SHOW:
			showTemplate( lowerCase( query ) );
			break;

		case CONSTRAINTS:
			printFormatted( lineLength, TRUE, stdout, 
				"This implementation supports the following constraints." );
			printFormatted( lineLength, TRUE, stdout, 
				"Local constraints are" );
			printFormatted( lineLength, TRUE, stdout, 
				"    match=(exact|fuzzy)" );
			printFormatted( lineLength, TRUE, stdout, 
				"Global constraints are" );
			printFormatted( lineLength, TRUE, stdout, 
				"    format=(full|abridged|handle|summary)" );
			printFormatted( lineLength, TRUE, stdout, 
				"    hold" );
			printFormatted( lineLength, TRUE, stdout, 
				"    language=<string>" );
			printFormatted( lineLength, TRUE, stdout, 
				"    linelength=<number>" );
			printFormatted( lineLength, TRUE, stdout, 
				"    maxhits=<number>" );
			break;

		case COMMAND:
			printFormatted( lineLength, TRUE, stdout,
				"Commands supported by this implementation are" );
			printFormatted( lineLength, TRUE, stdout,
				"    command" );
			printFormatted( lineLength, TRUE, stdout,
				"    constraints" );
			printFormatted( lineLength, TRUE, stdout,
				"    describe" );
			printFormatted( lineLength, TRUE, stdout,
				"    help" );
			printFormatted( lineLength, TRUE, stdout,
				"    list" );
			printFormatted( lineLength, TRUE, stdout,
				"    show" );
			printFormatted( lineLength, TRUE, stdout,
				"    version" );
			break;

		case ERROR:
			break;

		}
	} while ( holdConnection );
	closelog();
	ldap_unbind( ld );
}

static initialise()

{
	char	buffer[BUFSIZ];

	debug = FALSE;
	maxHits = DEFAULT_SIZELIMIT;
	maximumSize = maxHits;
	outputFormat = NULL;
	lineLength = DEFAULT_LINE_LENGTH;
	ldaphost = DEFAULT_LDAPHOST;
	defaultLanguage = DEFAULT_LANGUAGE;
	locale = "";
	base = NULL;
	contact = NULL;
	if ( gethostname( buffer, BUFSIZ ) == 0 )
		hostname = strdup( buffer );
	else
		hostname = NULL;
	user = NULL;
	password = NULL;
	helpDir = HELP_DIRECTORY;
	configDir = CONFIG_DIRECTORY;
	organisation = NULL;
	banner = NULL;
	log = FALSE;
	numberOfTemplates = 0;
	tableSize = TABLE_INCREMENT;
	templateTranslationTable = NULL;
}

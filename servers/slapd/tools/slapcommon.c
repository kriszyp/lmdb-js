/* slapcommon.c - common routine for the slap tools */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
 * Portions Copyright 2003 IBM Corporation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Kurt Zeilenga for inclusion
 * in OpenLDAP Software.  Additional signficant contributors include
 *    Jong Hyuk Choi
 *    Hallvard B. Furuseth
 *    Howard Chu
 *    Pierangelo Masarati
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slapcommon.h"
#include "lutil.h"


char	*progname	= NULL;
char	*conffile	= SLAPD_DEFAULT_CONFIGFILE;
int		truncatemode = 0;
int		verbose		= 0;
int		update_ctxcsn = SLAP_TOOL_CTXCSN_KEEP;
int		retrieve_ctxcsn = 0;
int		retrieve_synccookie = 0;
int		replica_promotion = 0;
int		replica_demotion = 0;
char	*replica_id_string = NULL;
char	**replica_id_strlist = NULL;
int		*replica_id_list = NULL;
int		continuemode = 0;
int		nosubordinates = 0;
int		dryrun = 0;
struct berval	sub_ndn = { 0, NULL };

char	*ldiffile	= NULL;
FILE	*ldiffp		= NULL;

#ifdef CSRIMALLOC
	char *leakfilename;
	FILE *leakfile;
#endif

Backend *be = NULL;

static void
usage( int tool )
{
	char *options = NULL;
	fprintf( stderr,
		"usage: %s [-v] [-c] [-d debuglevel] [-f configfile]\n"
			"\t[-n databasenumber | -b suffix]", progname );

	switch( tool ) {
	case SLAPADD:
		options = "\n\t[-l ldiffile] [-u] [-p [-w] | -r [-i syncreplidlist] [-w]]\n";
		break;

	case SLAPCAT:
		options = "\t[-l ldiffile] [-m] [-k]\n";
		break;

	case SLAPINDEX:
		options = "\n";
		break;
	}

	if( options != NULL ) {
		fputs( options, stderr );
	}
	exit( EXIT_FAILURE );
}


/*
 * slap_tool_init - initialize slap utility, handle program options.
 * arguments:
 *	name		program name
 *	tool		tool code
 *	argc, argv	command line arguments
 */

void
slap_tool_init(
	const char* name,
	int tool,
	int argc, char **argv )
{
	char *options;
	struct berval base = { 0, NULL };
	char *subtree = NULL;
	int rc, i, dbnum;
	int mode = SLAP_TOOL_MODE;

	progname = lutil_progname( name, argc, argv );

#ifdef CSRIMALLOC
	leakfilename = malloc( strlen( progname ) + sizeof(".leak") );
	sprintf( leakfilename, "%s.leak", progname );
	if( ( leakfile = fopen( leakfilename, "w" )) == NULL ) {
		leakfile = stderr;
	}
	free( leakfilename );
#endif

	switch( tool ) {
	case SLAPADD:
		options = "b:cd:f:i:l:n:prtuvWw";
		break;

	case SLAPINDEX:
		options = "b:cd:f:n:v";
		mode |= SLAP_TOOL_READMAIN;
		break;

	case SLAPCAT:
		options = "b:cd:f:kl:mn:s:v";
		mode |= SLAP_TOOL_READMAIN | SLAP_TOOL_READONLY;
		break;

	default:
		fprintf( stderr, "%s: unknown tool mode (%d)\n",
		         progname, tool );
		exit( EXIT_FAILURE );
	}

	ldiffile = NULL;
	conffile = SLAPD_DEFAULT_CONFIGFILE;
	dbnum = -1;
	while ( (i = getopt( argc, argv, options )) != EOF ) {
		switch ( i ) {
		case 'b':
			base.bv_val = strdup( optarg );
			base.bv_len = strlen( base.bv_val );
			break;

		case 'c':	/* enable continue mode */
			continuemode++;
			break;

		case 'd':	/* turn on debugging */
			ldap_debug += atoi( optarg );
			break;

		case 'f':	/* specify a conf file */
			conffile = strdup( optarg );
			break;

		case 'i': /* specify syncrepl id list */
			replica_id_string = strdup( optarg );
			if ( !isdigit( (unsigned char) *replica_id_string )) {
				usage( tool );
				exit( EXIT_FAILURE );
			}
			str2clist( &replica_id_strlist, replica_id_string, "," );
			for ( i = 0; replica_id_strlist && replica_id_strlist[i]; i++ ) ;
			replica_id_list = ch_calloc( i + 1, sizeof( int ) );
			for ( i = 0; replica_id_strlist && replica_id_strlist[i]; i++ ) {
				replica_id_list[i] = atoi( replica_id_strlist[i] );
				if ( replica_id_list[i] >= 1000 ) {
					fprintf(stderr,
						"%s: syncrepl id %d is out of range [0..999]\n",
						progname, replica_id_list[i] );
					exit( EXIT_FAILURE );
				}
			}
			replica_id_list[i] = -1;
			break;

		case 'k':	/* Retrieve sync cookie entry */
			retrieve_synccookie = 1;
			break;

		case 'l':	/* LDIF file */
			ldiffile = strdup( optarg );
			break;

		case 'm':	/* Retrieve ldapsync entry */
			retrieve_ctxcsn = 1;
			break;

		case 'n':	/* which config file db to index */
			dbnum = atoi( optarg ) - 1;
			break;

		case 'p':	/* replica promotion */
			replica_promotion = 1;		
			break;

		case 'r':	/* replica demotion */
			replica_demotion = 1;		
			break;

		case 's':	/* dump subtree */
			subtree = strdup( optarg );
			break;

		case 't':	/* turn on truncate */
			truncatemode++;
			mode |= SLAP_TRUNCATE_MODE;
			break;

		case 'u':	/* dry run */
			dryrun++;
			break;

		case 'v':	/* turn on verbose */
			verbose++;
			break;

		case 'W':	/* write context csn on every entry add */
			update_ctxcsn = SLAP_TOOL_CTXCSN_BATCH;
			/* FIXME : update_ctxcsn = SLAP_TOOL_CTXCSN_ENTRY; */
			break;

		case 'w':	/* write context csn on at the end */
			update_ctxcsn = SLAP_TOOL_CTXCSN_BATCH;
			break;

		default:
			usage( tool );
			break;
		}
	}

	if ( ( argc != optind ) || (dbnum >= 0 && base.bv_val != NULL ) ) {
		usage( tool );
	}

	if ( replica_promotion && replica_demotion ) {
		usage( tool );
	} else if ( !replica_promotion && !replica_demotion ) {
		if ( update_ctxcsn != SLAP_TOOL_CTXCSN_KEEP ) {
			usage( tool );
		}
	}

	if ( ldiffile == NULL ) {
		ldiffp = tool == SLAPCAT ? stdout : stdin;

	} else if( (ldiffp = fopen( ldiffile, tool == SLAPCAT ? "w" : "r" ))
		== NULL )
	{
		perror( ldiffile );
		exit( EXIT_FAILURE );
	}

	/*
	 * initialize stuff and figure out which backend we're dealing with
	 */

#ifdef SLAPD_MODULES
	if ( module_init() != 0 ) {
		fprintf( stderr, "%s: module_init failed!\n", progname );
		exit( EXIT_FAILURE );
	}
#endif
		
	rc = slap_init( mode, progname );

	if ( rc != 0 ) {
		fprintf( stderr, "%s: slap_init failed!\n", progname );
		exit( EXIT_FAILURE );
	}

	rc = slap_schema_init();

	if ( rc != 0 ) {
		fprintf( stderr, "%s: slap_schema_init failed!\n", progname );
		exit( EXIT_FAILURE );
	}

	rc = read_config( conffile, 0 );

	if ( rc != 0 ) {
		fprintf( stderr, "%s: bad configuration file!\n", progname );
		exit( EXIT_FAILURE );
	}

	if ( !nbackends ) {
		fprintf( stderr, "No databases found in config file\n" );
		exit( EXIT_FAILURE );
	}

	rc = glue_sub_init();

	if ( rc != 0 ) {
		fprintf( stderr, "Subordinate configuration error\n" );
		exit( EXIT_FAILURE );
	}

	rc = slap_schema_check();

	if ( rc != 0 ) {
		fprintf( stderr, "%s: slap_schema_prep failed!\n", progname );
		exit( EXIT_FAILURE );
	}

	if( subtree ) {
		struct berval val;
		val.bv_val = subtree;
		val.bv_len = strlen( subtree );
		rc = dnNormalize( 0, NULL, NULL, &val, &sub_ndn, NULL );
		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "Invalid subtree DN '%s'\n", optarg );
			exit( EXIT_FAILURE );
		}

		if( base.bv_val == NULL && dbnum == -1 )
			base = val;
		else
			free( subtree );
	}

	if( base.bv_val != NULL ) {
		struct berval nbase;

		rc = dnNormalize( 0, NULL, NULL, &base, &nbase, NULL );
		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: slap_init invalid suffix (\"%s\")\n",
				progname, base.bv_val );
			exit( EXIT_FAILURE );
		}

		be = select_backend( &nbase, 0, 0 );
		ber_memfree( nbase.bv_val );

		if( be == NULL ) {
			fprintf( stderr, "%s: slap_init no backend for \"%s\"\n",
				progname, base.bv_val );
			exit( EXIT_FAILURE );
		}
		/* If the named base is a glue master, operate on the
		 * entire context
		 */
		if (SLAP_GLUE_INSTANCE(be)) {
			nosubordinates = 1;
		}

	} else if ( dbnum == -1 ) {
		if ( nbackends <= 0 ) {
			fprintf( stderr, "No available databases\n" );
			exit( EXIT_FAILURE );
		}
		
		be = &backends[dbnum=0];
		/* If just doing the first by default and it is a
		 * glue subordinate, find the master.
		 */
		while (SLAP_GLUE_SUBORDINATE(be) || SLAP_MONITOR(be)) {
			if (SLAP_GLUE_SUBORDINATE(be)) {
				nosubordinates = 1;
			}
			be++;
			dbnum++;
		}


		if ( dbnum >= nbackends ) {
			fprintf( stderr, "Available database(s) "
					"do not allow %s\n", name );
			exit( EXIT_FAILURE );
		}
		
		if ( nosubordinates == 0 && dbnum > 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACKEND, ERR, 
"The first database does not allow %s; using the first available one (%d)\n",
				name, dbnum + 1, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
"The first database does not allow %s; using the first available one (%d)\n",
				name, dbnum + 1, 0 );
#endif
		}

	} else if ( dbnum < 0 || dbnum > (nbackends-1) ) {
		fprintf( stderr,
			"Database number selected via -n is out of range\n"
			"Must be in the range 1 to %d"
				" (number of databases in the config file)\n",
			nbackends );
		exit( EXIT_FAILURE );

	} else {
		be = &backends[dbnum];
	}

#ifdef CSRIMALLOC
	mal_leaktrace(1);
#endif

	if ( slap_startup( be ) ) {
		fprintf( stderr, "slap_startup failed\n" );
		exit( EXIT_FAILURE );
	}
}

void slap_tool_destroy( void )
{
	slap_shutdown( be );
	slap_destroy();
#ifdef SLAPD_MODULES
	if ( slapMode == SLAP_SERVER_MODE ) {
	/* always false. just pulls in necessary symbol references. */
		lutil_uuidstr(NULL, 0);
	}
	module_kill();
#endif
	schema_destroy();
#ifdef HAVE_TLS
	ldap_pvt_tls_destroy();
#endif
	config_destroy();

#ifdef CSRIMALLOC
	mal_dumpleaktrace( leakfile );
#endif
}

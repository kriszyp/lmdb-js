/* ldif2common.c - common definitions for the ldif2* tools */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldif2common.h"


char	*progname;
char	*tailorfile = SLAPD_DEFAULT_CONFIGFILE;
char	*inputfile	= NULL;
char	*sbindir    = LDAP_SBINDIR;             /* used by ldif2ldbm */
int 	cmdkids     = 1;                        /* used by ldif2ldbm */
int 	dbnum;


static void
usage( int tool )
{
	fprintf( stderr, "usage: %s %s\n\t%s%s\n",
			 progname, "-i inputfile [-d debuglevel] [-f configfile]",
			 "[-n databasenumber]",
			 ((tool == LDIF2LDBM)  ? " [-j #jobs] [-s sbindir]" :
			  (tool == LDIF2INDEX) ? " attr" :
			  "") );
	exit( EXIT_FAILURE );
}


/*
 * slap_ldif_init - initialize ldif utility, handle program options.
 * args: tool - which ldif2* program is running.
 *       argc, argv - from main.
 *       dbtype - "ldbm"/"bdb2".
 *       options - to getopt.
 */

void
slap_ldif_init( int argc, char **argv, int tool, const char *dbtype, int mode )
{
	char *options = (tool == LDIF2LDBM ? "e:s:j:d:f:i:n:" : "d:f:i:n:");
	int rc, i;

	progname = strrchr ( argv[0], '/' );
	progname = ch_strdup( progname ? progname + 1 : argv[0] );

	inputfile = NULL;
	tailorfile = SLAPD_DEFAULT_CONFIGFILE;
	dbnum = -1;
	while ( (i = getopt( argc, argv, options )) != EOF ) {
		switch ( i ) {
		case 'd':	/* turn on debugging */
			ldap_debug = atoi( optarg );
			break;

		case 's':	/* alternate sbindir (index cmd location) */
		case 'e':	/* accept -e for backwards compatibility */
			/* only used by ldif2ldbm and ldif2ldbm-bdb2 */
			sbindir = strdup( optarg );
			break;

		case 'f':	/* specify a tailor file */
			tailorfile = strdup( optarg );
			break;

		case 'i':	/* input file */
			inputfile = strdup( optarg );
			break;

		case 'j':	/* number of parallel index procs */
			/* only in ldif2ldbm and ldif2ldbm-bdb2 */
			cmdkids = atoi( optarg );
			break;

		case 'n':	/* which config file db to index */
			dbnum = atoi( optarg ) - 1;
			break;

		default:
			usage( tool );
			break;
		}
	}
	if ( inputfile == NULL || (argc != optind + (tool == LDIF2INDEX)) )
		usage( tool );

	if ( freopen( inputfile, "r", stdin ) == NULL ) {
		perror( inputfile );
		exit( EXIT_FAILURE );
	}

	/*
	 * initialize stuff and figure out which backend we're dealing with
	 */

	rc = slap_init( mode, progname );
	if (rc != 0 ) {
		fprintf( stderr, "%s: slap_init failed!\n", progname );
		exit( EXIT_FAILURE );
	}

	read_config( tailorfile );

	if ( dbnum == -1 ) {
		for ( dbnum = 0; dbnum < nbackends; dbnum++ ) {
			if ( strcasecmp( backends[dbnum].be_type, dbtype )
			    == 0 ) {
				break;
			}
		}
		if ( dbnum == nbackends ) {
			fprintf( stderr, "No %s database found in config file\n", dbtype );
			exit( EXIT_FAILURE );
		}
	} else if ( dbnum < 0 || dbnum > (nbackends-1) ) {
		fprintf( stderr, "Database number selected via -n is out of range\n" );
		fprintf( stderr, "Must be in the range 1 to %d (number of databases in the config file)\n", nbackends );
		exit( EXIT_FAILURE );
	} else if ( strcasecmp( backends[dbnum].be_type, dbtype ) != 0 ) {
		fprintf( stderr, "Database number %d selected via -n is not an %s database\n", dbnum, dbtype );
		exit( EXIT_FAILURE );
	}
}

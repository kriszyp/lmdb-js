#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldapconfig.h"
#include "../slap.h"
#include "../back-ldbm/back-ldbm.h"

#define MAXARGS      		100

static char	*tailorfile;
static char	*inputfile;
 
static void
usage( char *name )
{
	fprintf( stderr, "usage: %s -i inputfile [-d debuglevel] [-f configfile] [-n databasenumber]\n", name );
	exit( 1 );
}

int
main( int argc, char **argv )
{
	int		i, stop;
	char		*buf;
	char		line[BUFSIZ], idbuf[BUFSIZ];
	int      	lmax, lcur;
	int		dbnum;
	ID		id;
	struct dbcache	*db;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];
	FILE		*fp;

	tailorfile = SLAPD_DEFAULT_CONFIGFILE;
	dbnum = -1;
	while ( (i = getopt( argc, argv, "d:f:i:n:" )) != EOF ) {
		switch ( i ) {
		case 'd':	/* turn on debugging */
			ldap_debug = atoi( optarg );
			break;

		case 'f':	/* specify a tailor file */
			tailorfile = strdup( optarg );
			break;

		case 'i':	/* input file */
			inputfile = strdup( optarg );
			break;

		case 'n':	/* which config file db to index */
			dbnum = atoi( optarg ) - 1;
			break;

		default:
			usage( argv[0] );
			break;
		}
	}
	if ( inputfile == NULL ) {
		usage( argv[0] );
	} else {
		if ( freopen( inputfile, "r", stdin ) == NULL ) {
			perror( inputfile );
			exit( 1 );
		}
	}

	/*
	 * initialize stuff and figure out which backend we're dealing with
	 */

	slap_init(SLAP_TOOL_MODE, "ldif2id2entry");
	read_config( tailorfile );

	if ( dbnum == -1 ) {
		for ( dbnum = 0; dbnum < nbackends; dbnum++ ) {
			if ( strcasecmp( backends[dbnum].be_type, "ldbm" )
			    == 0 ) {
				break;
			}
		}
		if ( dbnum == nbackends ) {
			fprintf( stderr, "No ldbm database found in config file\n" );
			exit( 1 );
		}
	} else if ( dbnum < 0 || dbnum > (nbackends-1) ) {
		fprintf( stderr, "Database number selected via -n is out of range\n" );
		fprintf( stderr, "Must be in the range 1 to %d (number of databases in the config file)\n", nbackends );
		exit( 1 );
	} else if ( strcasecmp( backends[dbnum].be_type, "ldbm" ) != 0 ) {
		fprintf( stderr, "Database number %d selected via -n is not an ldbm database\n", dbnum );
		exit( 1 );
	}

	slap_startup(dbnum);

	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_NEWDB ))
	    == NULL ) {
		perror( "id2entry file" );
		exit( 1 );
	}

	id = 0;
	stop = 0;
	buf = NULL;
	lcur = lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( ! stop ) {
		Datum		key, data;

		ldbm_datum_init( key );
		ldbm_datum_init( data );

		if ( fgets( line, sizeof(line), stdin ) != NULL ) {
			int     len, idlen;

			len = strlen( line );
			if ( buf == NULL || *buf == '\0' ) {
				if (!isdigit((unsigned char) line[0])) {
					sprintf( idbuf, "%ld\n", id + 1 );
					idlen = strlen( idbuf );
				} else {
					id = atol(line) - 1;
					idlen = 0;
				}
			} else {
				idlen = 0;
			}

			while ( lcur + len + idlen + 1 > lmax ) {
				lmax += BUFSIZ;
				buf = (char *) ch_realloc( buf, lmax );
			}

			if ( idlen > 0 ) {
				strcpy( buf + lcur, idbuf );
				lcur += idlen;
			}
			strcpy( buf + lcur, line );
			lcur += len;
		} else {
			stop = 1;
		}
		if ( line[0] == '\n' || stop && buf && *buf ) {
			if ( *buf != '\n' ) {
				int len;

				id++;
				key.dptr = (char *) &id;
				key.dsize = sizeof(ID);
				data.dptr = buf;
				len = strlen(buf);
				if (buf[len - 1] == '\n')
					buf[--len] = '\0';
				data.dsize = len + 1;
				if ( ldbm_store( db->dbc_db, key, data,
				    LDBM_INSERT ) != 0 ) {
					fputs("id2entry ldbm_store failed\n",
					      stderr);
					exit( 1 );
				}
			}
			*buf = '\0';
			lcur = 0;
			line[0] = '\0';
		}
	}

#ifdef SLAP_CLEANUP
	ldbm_cache_close( be, db );
#endif

	slap_shutdown(dbnum);

	id++;
	sprintf( line, "%s/NEXTID",
	    ((struct ldbminfo *) be->be_private)->li_directory );
	if ( (fp = fopen( line, "w" )) == NULL ) {
		perror( line );
		fprintf( stderr, "Could not write next id %ld\n", id );
	} else {
		fprintf( fp, "%ld\n", id );
		fclose( fp );
	}

	slap_destroy();

	exit( 0 );
}

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldapconfig.h"
#include "../slap.h"
#include "../back-bdb2/back-bdb2.h"

#include "ldif.h"

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
	int		i, cargc, indb, stop, status;
	char		*cargv[MAXARGS];
	char		*defargv[MAXARGS];
	char		*linep, *buf;
	char		line[BUFSIZ];
	int		lineno, elineno;
	int      	lmax, lcur;
	int		dbnum;
	ID		id;
	struct dbcache	*db, *db2;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];
	Avlnode		*avltypes = NULL;

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

	slap_init(SLAP_TOOL_MODE, "ldif2id2children");
	read_config( tailorfile );

	if ( dbnum == -1 ) {
		for ( dbnum = 0; dbnum < nbackends; dbnum++ ) {
			if ( strcasecmp( backends[dbnum].be_type, "bdb2" )
			    == 0 ) {
				break;
			}
		}
		if ( dbnum == nbackends ) {
			fprintf( stderr, "No bdb2 database found in config file\n" );
			exit( 1 );
		}
	} else if ( dbnum < 0 || dbnum > (nbackends-1) ) {
		fprintf( stderr, "Database number selected via -n is out of range\n" );
		fprintf( stderr, "Must be in the range 1 to %d (number of databases in the config file)\n", nbackends );
		exit( 1 );
	} else if ( strcasecmp( backends[dbnum].be_type, "bdb2" ) != 0 ) {
		fprintf( stderr, "Database number %d selected via -n is not an bdb2 database\n", dbnum );
		exit( 1 );
	}

	slap_startup(dbnum);
	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	/*
	 * first, make the dn2id index
	 */

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX, LDBM_NEWDB ))
	    == NULL ) {
		perror( "dn2id file" );
		exit( 1 );
	}

	id = 0;
	stop = 0;
	lineno = 0;
	buf = NULL;
	lcur = lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( ! stop ) {
		char		*type, *val, *s;
		int		vlen;
		Datum		key, data;

		ldbm_datum_init( key );
		ldbm_datum_init( data );

		if ( fgets( line, sizeof(line), stdin ) != NULL ) {
			int     len;

			lineno++;
			len = strlen( line );
			while ( lcur + len + 1 > lmax ) {
				lmax += BUFSIZ;
				buf = (char *) ch_realloc( buf, lmax );
			}
			strcpy( buf + lcur, line );
			lcur += len;
		} else {
			stop = 1;
		}
		if ( line[0] == '\n' || stop && buf && *buf ) {
			if ( *buf != '\n' ) {
				if (isdigit((unsigned char) *buf)) {
					id = atol(buf);
				} else {
					id++;
				}
				s = buf;
				elineno = 0;
				while ( (linep = ldif_getline( &s )) != NULL ) {
					elineno++;
					if ( ldif_parse_line( linep, &type, &val,
					    &vlen ) != 0 ) {
						Debug( LDAP_DEBUG_PARSE,
			    "bad line %d in entry ending at line %d ignored\n",
						    elineno, lineno, 0 );
						continue;
					}

					if ( strcmp( type, "dn" ) == 0 )
						break;
				}

				if ( linep == NULL ) {
					fprintf( stderr, "entry %ld has no dn\n",
					    id );
				} else {
					key.dptr = dn_normalize_case( val );
					key.dsize = strlen( val ) + 1;
					data.dptr = (char *) &id;
					data.dsize = sizeof(ID);
					if ( ldbm_store( db->dbc_db, key, data,
					    LDBM_REPLACE ) != 0 ) {
						perror( "dn2id ldbm_store..." );
						exit( 1 );
					}
				}
			}
			*buf = '\0';
			lcur = 0;
			line[0] = '\0';
		}
	}
	if ( buf )
		free( buf );

	/*
	 * next, make the id2children index
	 */

	if ( (db2 = bdb2i_cache_open( be, "id2children", BDB2_SUFFIX,
	    LDBM_NEWDB )) == NULL ) {
		perror( "id2children file" );
		exit( 1 );
	}

	rewind( stdin );
	id = 0;
	stop = 0;
	buf = NULL;
	lineno = 0;
	lcur = lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( ! stop ) {
		char	*type, *val, *s, *dn;
		int	vlen;
		ID	pid;
		char	buf2[20];
		Datum	key, data;

		ldbm_datum_init( key );
		ldbm_datum_init( data );

		if ( fgets( line, sizeof(line), stdin ) != NULL ) {
			int     len;

			len = strlen( line );
			while ( lcur + len + 1 > lmax ) {
				lmax += BUFSIZ;
				buf = (char *) ch_realloc( buf, lmax );
			}
			strcpy( buf + lcur, line );
			lcur += len;
		} else {
			stop = 1;
		}
		if ( line[0] == '\n' || stop && buf && *buf ) {
			if ( * buf != '\n' ) {
				id++;
				s = buf;
				while ( (linep = ldif_getline( &s )) != NULL ) {
					if ( ldif_parse_line( linep, &type, &val,
					    &vlen ) != 0 ) {
						Debug( LDAP_DEBUG_PARSE,
						    "bad line %d ignored\n",
						    lineno, 0, 0 );
						continue;
					}

					if ( strcmp( type, "dn" ) == 0 )
						break;
				}

				if ( linep == NULL ) {
					fprintf( stderr, "entry %ld has no dn\n",
					    id );
				} else {
					if ( (dn = dn_parent( be, val ))
					    == NULL ) {
						pid = 0;
					} else {
						key.dptr =
						    dn_normalize_case( dn );
						key.dsize = strlen( dn ) + 1;

						data = ldbm_fetch( db->dbc_db,
						    key );
						free( dn );
						if ( data.dptr == NULL ) {
							dn_normalize_case( val );
							if ( ! be_issuffix( be,
							    val ) ) {
	Debug( LDAP_DEBUG_PARSE, "no parent \"%s\" of \"%s\"\n", dn, val, 0 );
							}
							*buf = '\0';
							lcur = 0;
							line[0] = '\0';
							continue;
						}
						(void) memcpy( (char *) &pid,
						    data.dptr, sizeof(ID) );

						ldbm_datum_free( db->dbc_db, data);
					}

					sprintf( buf2, "%c%ld", EQ_PREFIX, pid );
					key.dptr = buf2;
					key.dsize = strlen( buf2 ) + 1;
					if ( bdb2i_idl_insert_key( be, db2, key, id )
					    != 0 ) {
						perror( "bdb2i_idl_insert_key" );
						exit( 1 );
					}
				}
			}
			*buf = '\0';
			lcur = 0;
			line[0] = '\0';
		}
	}

	slap_shutdown(dbnum);
	slap_destroy();

	exit( 0 );
}

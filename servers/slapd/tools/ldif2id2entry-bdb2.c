#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldif2common.h"
#include "../back-bdb2/back-bdb2.h"

int
main( int argc, char **argv )
{
	int		i, stop;
	char		*buf;
	char		line[BUFSIZ], idbuf[BUFSIZ];
	int      	lmax, lcur;
	ID		id;
	ID		maxid;
	struct dbcache	*db;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];
	FILE		*fp;

	slap_ldif_init( argc, argv, LDIF2ID2ENTRY, "bdb2", SLAP_TOOLID_MODE );

	slap_startup(dbnum);

	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	if ( (db = bdb2i_cache_open( be, "id2entry", BDB2_SUFFIX, LDBM_NEWDB ))
	    == NULL ) {
		perror( "id2entry file" );
		exit( EXIT_FAILURE );
	}

	id = 0;
	maxid = 0;
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
 				if ( id > maxid )
 					maxid = id;
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
					exit( EXIT_FAILURE );
				}
			}
			*buf = '\0';
			lcur = 0;
			line[0] = '\0';
		}
	}

	maxid++;
	bdb2i_put_nextid( be, maxid );

#ifdef SLAP_CLEANUP
	bdb2i_cache_close( be, db );
#endif

	slap_shutdown(dbnum);

	slap_destroy();

	exit( EXIT_SUCCESS );
}

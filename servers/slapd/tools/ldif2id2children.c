/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldif2common.h"
#include "../back-ldbm/back-ldbm.h"
#include "ldif.h"

int
main( int argc, char **argv )
{
	int		stop;
	char		*linep, *buf;
	char		line[BUFSIZ];
	int		lineno, elineno;
	int      	lmax, lcur;
	ID		id;
	DBCache	*db, *db2;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];

	ldbm_ignore_nextid_file = 1;

	slap_ldif_init( argc, argv, LDIF2ID2CHILDREN, "ldbm", SLAP_TOOL_MODE );

	slap_startup(dbnum);
	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	/*
	 * first, make the dn2id index
	 */

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_NEWDB ))
	    == NULL ) {
		perror( "dn2id file" );
		exit( EXIT_FAILURE );
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
		ber_len_t		vlen;
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
					(void) dn_normalize_case( val );
					key.dptr = val;
					key.dsize = strlen( val ) + 1;
					data.dptr = (char *) &id;
					data.dsize = sizeof(ID);
					if ( ldbm_store( db->dbc_db, key, data,
					    LDBM_REPLACE ) != 0 ) {
						perror( "dn2id ldbm_store" );
						exit( EXIT_FAILURE );
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

	if ( (db2 = ldbm_cache_open( be, "id2children", LDBM_SUFFIX,
	    LDBM_NEWDB )) == NULL ) {
		perror( "id2children file" );
		exit( EXIT_FAILURE );
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
		ber_len_t	vlen;
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
				if (isdigit((unsigned char) *buf)) {
					id = atol(buf);
				} else {
					id++;
				}
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
						(void) dn_normalize_case( dn );
						key.dptr = dn;
						key.dsize = strlen( dn ) + 1;

						data = ldbm_fetch( db->dbc_db,
						    key );
						free( dn );
						if ( data.dptr == NULL ) {
							(void) dn_normalize_case( val );
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
					if ( idl_insert_key( be, db2, key, id )
					    != 0 ) {
						perror( "idl_insert_key" );
						exit( EXIT_FAILURE );
					}
				}
			}
			*buf = '\0';
			lcur = 0;
			line[0] = '\0';
		}
	}

#ifdef SLAP_CLEANUP
	ldbm_cache_close( be, db2 );
	ldbm_cache_close( be, db );
#endif

	slap_shutdown(dbnum);
	slap_destroy();

	return( EXIT_SUCCESS );
}

/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>
#include <limits.h>

#include <ac/stdlib.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "../slap.h"
#include "../back-ldbm/back-ldbm.h"

static DBCache	*openchoice(char c, int mode, int verbose, char **fname);
static void		print_entry(FILE *fp, char c, Datum *key, char *klabel, Datum *data, char *dlabel);
static void		free_and_close(DBCache *dbc, Datum key, Datum data);
static void		edit_entry(char c, Datum *data);
static void		get_keydata(FILE *fp, char c, Datum *key, Datum *data);

static DBCache *dbc;
static LDBM           dbp;
static Backend		*be = NULL;

int
main( int argc, char **argv )
{
	char		buf[256];
	Datum		savekey, key, data, last;
	char		*fname;
	ID		id, cursor;
	ID_BLOCK		*idl;
	Backend		*tbe;
	int		i;
	char 		*tailorfile;

	LDBMCursor	*cursorp;

	fprintf(stderr,
		"ldbmtest not updated to support new index formats!\n" );
	exit( EXIT_FAILURE );


	ldbm_datum_init( savekey );
	ldbm_datum_init( key );
	ldbm_datum_init( data );
	ldbm_datum_init( last );

	tailorfile = SLAPD_DEFAULT_CONFIGFILE;
	while ( (i = getopt( argc, argv, "d:f:" )) != EOF ) {
		switch ( i ) {
		case 'd':	/* turn on debugging */
			ldap_debug = atoi( optarg );
			break;

		case 'f':	/* specify a tailor file */
			tailorfile = strdup( optarg );
			break;

		default:
			fprintf( stderr,
			    "usage: %s [-d level] [-f slapdconfigfile]\n",
			    argv[0] );
			exit( EXIT_FAILURE );
		}
	}

	/*
	 * initialize stuff and figure out which backend we're dealing with
	 */

	slap_init(SLAP_TOOL_MODE, "ldbmtest");
	read_config( tailorfile );
	slap_startup( NULL );

	while ( 1 ) {
		printf( "dbtest: " );

		if ( fgets( buf, sizeof(buf), stdin ) == NULL )
			break;

		switch ( buf[0] ) {
		case 'c':	/* create an index */
			fname = NULL;
			if ( (dbc = openchoice( buf[1], LDBM_READER, 0,
			    &fname )) != NULL ) {
				printf( "Already exists\n" );
				ldbm_close( dbc->dbc_db );
				break;
			}
			if ( (dbc = openchoice( buf[1], LDBM_WRCREAT, 1,
			    &fname )) != NULL ) {
				ldbm_close( dbc->dbc_db );
			}
			break;

		case 'l':	/* lookup something in an index */
			if ( (dbc = openchoice( buf[1], LDBM_READER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, NULL );
			data = ldbm_fetch( dbc->dbc_db, key );
			print_entry( stdout, buf[1], &key, "key: ", &data,
			    "data:\n" );

			free_and_close( dbc, key, data );
			break;

		case 'L':	/* get all blocks for a key from an index */
			if ( (dbc = openchoice( buf[1], LDBM_READER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, NULL );
			if ( (idl = idl_fetch( be, dbc, key )) != NULL ) {
				data.dptr = (char *) idl;
				data.dsize = (ID_BLOCK_NMAX(idl) + 1) * sizeof(ID);
				print_entry( stdout, buf[1], &key, "key: ",
				    &data, "data:\n" );
			}
			free_and_close( dbc, key, data );
			break;

		case 't':	/* traverse */
		case 'T':	/* traverse - keys only */
			if ( (dbc = openchoice( buf[1], LDBM_READER, 1, NULL ))
			    == NULL ) {
				perror( "openchoice" );
				continue;
			}

			savekey.dptr = NULL;
			for ( key = ldbm_firstkey( dbc->dbc_db, &cursorp );
			    key.dptr != NULL;
			    key = ldbm_nextkey( dbc->dbc_db, key, cursorp ) )
			{
				if ( savekey.dptr != NULL )
					ldbm_datum_free( dbc->dbc_db, savekey );
				savekey = key;

				data = ldbm_fetch( dbc->dbc_db, key );

				if ( buf[0] == 't' ) {
					print_entry( stdout, buf[1], &key,
					    "key: ", &data, "data:\n" );
				} else {
					print_entry( stdout, buf[1], &key,
					    "key: ", NULL, NULL );
				}

                if ( data.dptr != NULL ) {
				    ldbm_datum_free( dbc->dbc_db, data );
                }
			}
			if ( savekey.dptr != NULL )
				ldbm_datum_free( dbc->dbc_db, savekey );

			ldbm_close( dbc->dbc_db );
			break;

		case 'x':	/* delete an entry */
			if ( (dbc = openchoice( buf[1], LDBM_WRITER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, NULL );

			if ( ldbm_delete( dbc->dbc_db, key ) != 0 ) {
				if ( ldbm_errno( dbc->dbc_db ) == 0 ) {
					perror( "ldbm_delete" );
				} else {
					fprintf( stderr, "db_errno=%d",
					    ldbm_errno( dbc->dbc_db ) );
				}
			}

			data.dptr = NULL;
			free_and_close( dbc, key, data );
			break;

#ifndef HAVE_WINSOCK
		case 'e':	/* edit an entry */
			if ( (dbc = openchoice( buf[1], LDBM_WRITER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, NULL );

			data = ldbm_fetch( dbc->dbc_db, key );
			if ( data.dptr == NULL ) {
				if ( ldbm_errno( dbc->dbc_db ) == 0 ) {
					perror( "ldbm_fetch" );
				} else {
					fprintf( stderr, "db_errno=%d\n",
					    ldbm_errno( dbc->dbc_db ) );
				}
				free_and_close( dbc, key, data );
				break;
			}

			edit_entry( buf[1], &data );

			if ( data.dptr == NULL ) {
				if ( ldbm_delete( dbc->dbc_db, key ) != 0 ) {
					perror( "ldbm_delete" );
				}
			} else if ( ldbm_store( dbc->dbc_db, key, data,
			    LDBM_REPLACE ) != 0 ) {
				if ( ldbm_errno( dbc->dbc_db ) == 0 ) {
					perror( "ldbm_store" );
				} else {
					fprintf( stderr, "db_errno=%d\n",
					    ldbm_errno( dbc->dbc_db ) );
				}
			}

			free_and_close( dbc, key, data );
			break;
#endif

		case 'a':	/* add an entry */
			if ( (dbc = openchoice( buf[1], LDBM_WRITER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, &data );

			if ( ldbm_store( dbc->dbc_db, key, data, LDBM_INSERT )
			    != 0 ) {
				if ( ldbm_errno( dbc->dbc_db ) == 0 ) {
					perror( "ldbm_store" );
				} else {
					fprintf( stderr, "db_errno=%d\n",
					    ldbm_errno( dbc->dbc_db ) );
				}
			}

			free_and_close( dbc, key, data );
			break;

		case 'i':	/* insert an id into an index entry */
			if ( (dbc = openchoice( buf[1], LDBM_WRITER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			get_keydata( stdin, buf[1], &key, &data );

			idl = (ID_BLOCK *) data.dptr;
			for ( id = idl_firstid( idl, &cursor ); id != NOID;
			    id = idl_nextid( idl, &cursor ) ) {
				if ( idl_insert_key( be, dbc, key, id )
				    != 0 ) {
					fprintf( stderr,
					    "idl_insert_key (%s) %ld failed\n",
					    key.dptr, id );
					continue;
				}
			}

			free_and_close( dbc, key, data );
			break;

		case 'b':	/* select a backend by suffix */
			printf( "suffix: " );
			fflush( stdout );
			if ( fgets( buf, sizeof(buf), stdin ) == NULL ) {
				exit( EXIT_SUCCESS );
			} else {
				buf[strlen( buf ) - 1] = '\0';
			}
			(void) dn_normalize_case( buf );
			if ( (tbe = select_backend( buf )) == NULL ) {
				fprintf( stderr, "unknown suffix \"%s\"\n",
				    buf );
			} else {
				be = tbe;
			}
			break;

		case 'B':	/* print current suffix */
			if ( be == NULL ) {
				printf( "no current backend\n" );
			} else {
				printf( "current backend has suffix \"%s\"\n",
				    be->be_suffix[0] );
			}
			break;

		case 'C':	/* produce concordance of an index */
			if ( (dbc = openchoice( 'i', LDBM_READER, 1, NULL ))
			    == NULL ) {
				continue;
			}

			last.dptr = NULL;

			for ( key = ldbm_firstkey( dbp, &cursorp );
				key.dptr != NULL;
				key = ldbm_nextkey( dbp, last, cursorp ) )
			{
				if ( last.dptr != NULL ) {
					ldbm_datum_free( dbp, last );
				}
				last = key;
				printf( "key(%d): (%s)\n", key.dsize,
				    key.dptr );
			}

			free_and_close( dbc, key, last );
			break;

		default:
			printf( "commands: l<c> => lookup index\n" );
			printf( "          L<c> => lookup index (all)\n" );
			printf( "          t<c> => traverse index\n" );
			printf( "          T<c> => traverse index keys\n" );
			printf( "          x<c> => delete from index\n" );
			printf( "          e<c> => edit index entry\n" );
			printf( "          a<c> => add index entry\n" );
			printf( "          c<c> => create index\n" );
			printf( "          i<c> => insert ids into index\n" );
			printf( "          b    => change default backend\n" );
			printf( "          B    => print default backend\n" );
			printf( "where <c> is a char selecting the index:\n" );
			printf( "          d => dn2id\n" );
			printf( "          e => id2entry\n" );
			printf( "          f => arbitrary file\n" );
			printf( "          i => attribute index\n" );
			break;
		}
	}

	slap_shutdown( NULL );
	slap_destroy();

	return( EXIT_SUCCESS );
}

static void
free_and_close( DBCache *dbc, Datum key, Datum data )
{
	ldbm_cache_really_close( be, dbc );
	if ( key.dptr != NULL )
		ldbm_datum_free( dbp, key );
	if ( data.dptr != NULL )
		ldbm_datum_free( dbp, data );
}

static int
dnid_cmp( const void *a, const void *b )
{
	return( *(const long int *)a - *(const long int *)b );
}

static char *
myrealloc( char *p, int size )
{
	if ( p == NULL )
		return( (char *) malloc( size ) );
	else
		return( (char *) realloc( p, size ) );
}

static void
get_idlist( FILE *fp, Datum *data )
{
	char	buf[20];
	int	i, fd, tty;
	ID_BLOCK	*p;
	unsigned int	psize, pmax;
	unsigned int	nmax, nids;

	fd = fileno( fp );
	tty = isatty( fd );

	p = NULL;
	psize = 2 * sizeof(ID);
	pmax = 0;
	nmax = 0;
	nids = 0;
	i = 0;
	while ( 1 ) {
		if ( tty )
			printf( "id? " );
		if ( fgets( buf, sizeof(buf), fp ) == NULL || buf[0] == '\n' )
			break;
		if ( strncmp( buf, "nmax=", 5 ) == 0 ) {
			nmax = atol( buf + 5 );
			continue;
		}

		if ( psize + sizeof(ID) > pmax ) {
			pmax += BUFSIZ;
			p = (ID_BLOCK *) myrealloc( (char *) p, pmax );
		}

		if ( strncmp( buf, "nids=0", 6 ) == 0 ) {
			nids = NOID;
			continue;
		}

		ID_BLOCK_ID(p,i++) = atol( buf );
		psize += sizeof(ID);
	}
	if ( nmax == 0 ) {
		if ( tty ) {
			nmax = i;
			printf( "%d IDs entered.  Max number of ids? [%d] ", i,
			    i );
			if ( fgets( buf, sizeof(buf), fp ) != NULL &&
			     isdigit( (unsigned char) buf[0] ) ) {
				nmax = atol( buf );
			}
		} else {
			nmax = i;
		}
	}
	if ( i > 0 ) {
		ID_BLOCK_NMAX(p) = nmax;
		if ( nids != 0 ) {
			ID_BLOCK_NIDS(p) = 0;
			ID_BLOCK_ID(p,i) = NOID;
		} else {
			ID_BLOCK_NIDS(p) = i;
		}

		qsort( (void *) &ID_BLOCK_ID(p, 0), i, sizeof(ID), dnid_cmp );
	}

	data->dptr = (char *) p;
	data->dsize = (nmax + ID_BLOCK_IDS_OFFSET) * sizeof(ID);
}

static void
get_entry( FILE *fp, Datum *data )
{
	char	buf[BUFSIZ];
	char	*p;
	unsigned int	pmax, psize, len;
	int	fd;

	fd = fileno( fp );
	if ( isatty( fd ) )
		printf( "Enter entry, <cr><cr> to end:\n" );

	p = NULL;
	pmax = psize = 0;
	while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
		len = strlen( buf );
		if ( psize + strlen( buf ) > pmax ) {
			pmax += BUFSIZ;
			p = myrealloc( p, pmax );
		}
		if ( psize == 0 )
			strcpy( p, buf );
		else
			strcat( p, buf );
		psize += len;

		if ( buf[0] == '\n' )
			break;
	}

	data->dptr = p;
	data->dsize = psize + 1;
}

#ifndef HAVE_WINSOCK
static void
edit_entry( char c, Datum *data )
{
	int		fd, pid;
	char		tmpname[20];
	FILE		*fp;
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE	status;
#endif

	strcpy( tmpname, "/tmp/dbtestXXXXXX" );
#ifndef HAVE_MKSTEMP
	if ( (fd = open( mktemp( tmpname ), O_RDWR, 0600 )) == -1 ) {
		perror( tmpname );
		return;
	}
#else
	if ( (fd = mkstemp( tmpname )) == -1 ) {
		perror( tmpname );
		return;
	}
#endif

	fp = fdopen( fd, "w" );
	print_entry( fp, c, NULL, NULL, data, NULL );
	fflush( fp );

	pid = fork();

	if ( pid == -1 ) {
		perror( "fork" );
		return;
	} else if ( pid == 0 ) {
		char	*editor;

		if ( (editor = getenv( "EDITOR" )) == NULL ) {
			editor = LDAP_EDITOR;
		}
		execl( editor, editor, tmpname, NULL );
		perror( "execl" );
		exit( EXIT_FAILURE );
	}

	fclose( fp );
 
#ifdef HAVE_WAITPID
	if ( waitpid( (pid_t) -1, NULL, WAIT_FLAGS ) < 0 )
#else
	if ( wait3( (pid_t) -1, &status, WAIT_FLAGS, 0 ) < 0 )
#endif
	{
		perror( "wait" );
		return;
	}

	if ( (fp = fopen( tmpname, "r" )) == NULL ) {
		perror( tmpname );
		return;
	}
    if ( data->dptr != NULL ) {
	    ldbm_datum_free( NULL, *data );
    }
	get_keydata( fp, c, NULL, data );
	fclose( fp );
	unlink( tmpname );
}
#endif

static DBCache *
openfile( char *name, int namesiz, int mode, int verbose, char c )
{
	DBCache	*dbc;

	if ( name == NULL || *name == '\0' ) {
		if ( c == 'f' ) {
			printf( "  file: " );
			if ( fgets( name, namesiz, stdin ) == NULL )
				exit( EXIT_SUCCESS );
			name[strlen( name ) - 1] = '\0';
		} else {
			printf( "  attr: " );
			if ( fgets( name, namesiz, stdin ) == NULL )
				exit( EXIT_SUCCESS );
			name[strlen( name ) - 1] = '\0';
		}
	}

	if ( (dbc = ldbm_cache_open( be, name, (c == 'f') ? "" : LDBM_SUFFIX,
	    LDBM_READER )) == NULL ) {
		perror( name );
	} else {
		dbp = dbc->dbc_db;
	}

	return( dbc );
}

static DBCache *
openchoice( char c, int mode, int verbose, char **fname )
{
	static char	name[MAXPATHLEN];

	switch ( c ) {
	case 'd':	/* dn2id */
		sprintf( name, "dn2id" );
		break;
	case 'e':	/* id2entry */
		sprintf( name, "id2entry" );
		break;
	case 'f':	/* arbitrary file */
	case 'i':	/* index */
		if ( fname != NULL && *fname != NULL ) {
			strcpy( name, *fname );
		} else {
			name[0] = '\0';
		}
		break;
	default:
		printf( "specify one of [fdei] to select file\n" );
		return( NULL );
		break;
	}
	if ( fname != NULL ) {
		*fname = name;
	}

	return( openfile( name, MAXPATHLEN, mode, verbose, c ) );
}

static void
print_entry(
	FILE	*fp,
	char	c,
	Datum	*key,
	char	*klabel,
	Datum	*data,
	char	*dlabel
)
{
	ID	id;
	ID_BLOCK	*idl;
	unsigned int	i;
	char	msg[2];

	if ( data != NULL && data->dptr == NULL ) {
		msg[0] = c;
		msg[1] = '\0';

		if ( ldbm_errno( dbp ) == 0 )
			perror( msg );
		else
			fprintf( stderr, "%s: db_errno=%d\n", msg,
			    ldbm_errno( dbp ) );
		return;
	}

	switch ( c ) {
	case 'd':	/* dn2id - key is dn, data is dnid */
		if ( key != NULL )
			fprintf( fp, "%s%s (len %d)\n", klabel, key->dptr,
			    key->dsize );
		if ( data != NULL ) {
			SAFEMEMCPY( (char *) &id, data->dptr, sizeof(ID) );
			fprintf( fp, "%s%ld\n", dlabel ? dlabel : "", id );
		}
		break;

	case 'e':	/* id2entry - key is dnid, data is entry */
		if ( key != NULL ) {
			SAFEMEMCPY( (char *) &id, key->dptr, sizeof(ID) );
			fprintf( fp, "%s %ld\n", klabel, id );
		}
		if ( data != NULL ) {
			if ( dlabel ) {
				fprintf( fp, "data length: %d\n", data->dsize );
				fputs( dlabel, fp );
			}
			fputs( data->dptr, fp );
		}
		break;

	case 'i':	/* index - key is string, data is dnid[] */
		if ( key != NULL )
			fprintf( fp, "%s%s (len %d)\n", klabel, key->dptr,
			    key->dsize );
		if ( data != NULL ) {
			idl = (ID_BLOCK *) data->dptr;

			if ( dlabel )
				fprintf( fp, "%s\tnmax=%ld\n\tncur=%ld\n", dlabel,
				    ID_BLOCK_NMAX(idl), ID_BLOCK_NIDS(idl) );

			if ( ID_BLOCK_INDIRECT( idl ) ) {
				for ( i = 0; !ID_BLOCK_NOID(idl, i); i++ ) {
					fprintf( fp, "\t%ld\n", ID_BLOCK_ID(idl, i) );
				}
			} else if ( ID_BLOCK_ALLIDS( idl ) ) {
				fprintf( fp, "\tALLIDS\n" );
			} else {
				for ( i = 0; i < ID_BLOCK_NIDS(idl); i++ ) {
					fprintf( fp, "\t%ld\n", ID_BLOCK_ID(idl,i) );
				}
			}
		}
		break;

	case 'f':	/* arbitrary file - assume key & data are strings */
		if ( key != NULL )
			fprintf( fp, "%s%s\n", klabel, key->dptr );
		if ( data != NULL ) {
			fprintf( fp, "%s%s\n", dlabel ? dlabel : "",
			    data->dptr );
		}
		break;

	default:
		fprintf( stderr, "specify [dei] to select a file\n" );
		break;
	}
}

static void
get_keydata( FILE *fp, char c, Datum *key, Datum *data )
{
	static char	kbuf[BUFSIZ], dbuf[BUFSIZ];
	long		n;
	int		fd, tty;

	fd = fileno( fp );
	tty = isatty( fd );

	switch ( c ) {
	case 'd':	/* dn2id - key is dn, data is dnid */
		if ( key != NULL ) {
			if ( tty )
				printf( "  dn: " );
			if ( fgets( kbuf, sizeof(kbuf), fp ) == NULL ) {
				exit( EXIT_SUCCESS );
			}
			kbuf[strlen( kbuf ) - 1] = '\0';
			key->dptr = strdup( kbuf );
			key->dsize = strlen( kbuf ) + 1;
		}

		if ( data != NULL ) {
			if ( tty )
				printf( "  dnid: " );
			if ( fgets( dbuf, sizeof(dbuf), fp ) == NULL ) {
				exit( EXIT_SUCCESS );
			}
			n = atol( dbuf );
			data->dptr = (char *) malloc( sizeof(n) );
			memcpy( data->dptr, (char *) &n, sizeof(n) );
			data->dsize = sizeof(n);
		}
		break;

	case 'e':	/* id2entry - key is dnid, data is entry */
		if ( key != NULL ) {
			if ( tty )
				printf( "  dnid: " );
			if ( fgets( kbuf, sizeof(kbuf), fp ) == NULL ) {
				exit( EXIT_SUCCESS );
			}
			n = atol( kbuf );
			key->dptr = (char *) malloc( sizeof(n) );
			memcpy( key->dptr, (char *) &n, sizeof(n) );
			key->dsize = sizeof(n);
		}

		if ( data != NULL ) {
			get_entry( fp, data );
		}
		break;

	case 'i':	/* index - key is string, data is dnid[] */
		if ( key != NULL ) {
			if ( tty )
				printf( "  key: " );
			if ( fgets( kbuf, sizeof(kbuf), fp ) == NULL ) {
				exit( EXIT_SUCCESS );
			}
			kbuf[strlen( kbuf ) - 1] = '\0';
			key->dptr = strdup( kbuf );
			key->dsize = strlen( kbuf ) + 1;
		}

		if ( data != NULL ) {
			get_idlist( fp, data );
		}
		break;

	default:
		fprintf(stderr, "specify [dei] to select file type\n");
		break;
	}
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <limits.h>
#include "portable.h"
#include "ldapconfig.h"
#include "../slap.h"
#include "../back-ldbm/back-ldbm.h"

#define EDITOR	"/usr/ucb/vi"

extern IDList		*idl_fetch();
extern Backend		*select_backend();
extern struct dbcache	*ldbm_cache_open();

static struct dbcache	*openchoice();
static void		print_entry();
static void		free_and_close();
static void		edit_entry();
static void		get_keydata();

struct dbcache	*dbc;
LDBM		dbp;
char		*tailorfile;
Backend		*be = NULL;
int		ldap_debug;
int		ldap_syslog;
int		ldap_syslog_level;
int		global_schemacheck;
int		num_entries_sent;
int		num_bytes_sent;
int		active_threads;
char		*default_referral;
struct objclass	*global_oc;
time_t		currenttime;
pthread_t	listener_tid;
pthread_mutex_t	num_sent_mutex;
pthread_mutex_t	entry2str_mutex;
pthread_mutex_t	active_threads_mutex;
pthread_mutex_t	new_conn_mutex;
pthread_mutex_t	currenttime_mutex;
pthread_mutex_t	replog_mutex;
pthread_mutex_t	ops_mutex;
pthread_mutex_t	regex_mutex;

main( argc, argv )
    int		argc;
    char	**argv;
{
	char		buf[256];
	Datum		savekey, key, data, last;
	char		*fname;
	ID		id;
	IDList		*idl;
	Backend		*tbe;
	int		i;
	extern char	*optarg;

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
			exit( -1 );
			break;
		}
	}

	/*
	 * initialize stuff and figure out which backend we're dealing with
	 */

	init();
	read_config( tailorfile, &be, NULL );

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

		case 'l':	/* lookup somethig in an index */
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
				data.dsize = (idl->b_nmax + 1) * sizeof(ID);
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
			for ( key = ldbm_firstkey( dbc->dbc_db );
			    key.dptr != NULL;
			    key = ldbm_nextkey( dbc->dbc_db, key ) ) {
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

				ldbm_datum_free( dbc->dbc_db, data );
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
					fprintf( stderr, "db_errno %d",
					    ldbm_errno( dbc->dbc_db ) );
				}
			}

			data.dptr = NULL;
			free_and_close( dbc, key, data );
			break;

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
					fprintf( stderr, "db_errno %d\n",
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
					fprintf( stderr, "db_errno %d\n",
					    ldbm_errno( dbc->dbc_db ) );
				}
			}

			free_and_close( dbc, key, data );
			break;

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
					fprintf( stderr, "db_errno %d\n",
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

			idl = (IDList *) data.dptr;
			for ( id = idl_firstid( idl ); id != NOID;
			    id = idl_nextid( idl, id ) ) {
				if ( idl_insert_key( be, dbc, key, id )
				    != 0 ) {
					fprintf( stderr,
					    "idl_insert_key (%s) %d failed\n",
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
				exit( 0 );
			} else {
				buf[strlen( buf ) - 1] = '\0';
			}
			(void) dn_normalize( buf );
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
			for ( key = ldbm_firstkey( dbp ); key.dptr != NULL;
			    key = ldbm_nextkey( dbp, last ) ) {
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
			printf( "          c => id2children\n" );
			printf( "          d => dn2id\n" );
			printf( "          e => id2entry\n" );
			printf( "          f => arbitrary file\n" );
			printf( "          i => attribute index\n" );
			break;
		}
	}

	return( 0 );
}

static void
free_and_close( dbc, key, data )
    struct dbcache	*dbc;
    Datum		key;
    Datum		data;
{
	ldbm_cache_really_close( be, dbc );
	if ( key.dptr != NULL )
		ldbm_datum_free( dbp, key );
	if ( data.dptr != NULL )
		ldbm_datum_free( dbp, data );
}

static int
dnid_cmp( a, b )
    long	*a;
    long	*b;
{
	return( *a - *b );
}

static char *
myrealloc( p, size )
    char	*p;
    int		size;
{
	if ( p == NULL )
		return( (char *) malloc( size ) );
	else
		return( (char *) realloc( p, size ) );
}

static void
get_idlist( fp, data )
    FILE	*fp;
    Datum	*data;
{
	char	buf[20];
	int	i, j, fd, tty;
	IDList	*p;
	int	psize, pmax;
	int	nmax, nids;

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
			p = (IDList *) myrealloc( (char *) p, pmax );
		}

		if ( strncmp( buf, "nids=0", 6 ) == 0 ) {
			nids = NOID;
			continue;
		}

		p->b_ids[i++] = atol( buf );
		psize += sizeof(ID);
	}
	if ( nmax == 0 ) {
		if ( tty ) {
			nmax = i;
			printf( "%d IDs entered.  Max number of ids? [%d] ", i,
			    i );
			if ( fgets( buf, sizeof(buf), fp ) != NULL &&
			    isdigit( buf[0] ) ) {
				nmax = atol( buf );
			}
		} else {
			nmax = i;
		}
	}
	if ( i > 0 ) {
		p->b_nmax = nmax;
		if ( nids != 0 ) {
			p->b_nids = 0;
			p->b_ids[i] = NOID;
		} else {
			p->b_nids = i;
		}

		qsort( (void *) p->b_ids, i, sizeof(ID), (void *) dnid_cmp );
	}

	data->dptr = (char *) p;
	data->dsize = (nmax + 2) * sizeof(ID);
}

static void
get_entry( fp, data )
    FILE	*fp;
    Datum	*data;
{
	char	buf[BUFSIZ];
	char	*p;
	int	pmax, psize, len;
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

static void
edit_entry( c, data )
    char	c;
    Datum	*data;
{
	int		fd, pid;
	char		tmpname[20];
	FILE		*fp;
	WAITSTATUSTYPE	status;

	strcpy( tmpname, "/tmp/dbtestXXXXXX" );
#ifdef ultrix
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
			editor = EDITOR;
		}
		execl( editor, editor, tmpname, NULL );
		perror( "execl" );
		exit( 1 );
	}

	fclose( fp );
 
#ifdef USE_WAITPID
	if ( waitpid( (pid_t) -1, 0, WAIT_FLAGS ) < 0 ) {
#else
	if ( wait3( &status, WAIT_FLAGS, 0 ) < 0 ) {
#endif
		perror( "wait" );
		return;
	}

	if ( (fp = fopen( tmpname, "r" )) == NULL ) {
		perror( tmpname );
		return;
	}
	ldbm_datum_free( NULL, *data );
	get_keydata( fp, c, NULL, data );
	fclose( fp );
	unlink( tmpname );
}

static struct dbcache *
openfile( name, namesiz, mode, verbose, c )
    char	*name;
    int		namesiz;
    int		mode;
    int		verbose;
    char	c;
{
	struct dbcache	*dbc;

	if ( name == NULL || *name == '\0' ) {
		if ( c == 'f' ) {
			printf( "  file: " );
			if ( fgets( name, namesiz, stdin ) == NULL )
				exit( 0 );
			name[strlen( name ) - 1] = '\0';
		} else {
			printf( "  attr: " );
			if ( fgets( name, namesiz, stdin ) == NULL )
				exit( 0 );
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

static struct dbcache *
openchoice( c, mode, verbose, fname )
    char	c;
    int		mode;
    int		verbose;
    char	**fname;
{
	static char	name[MAXPATHLEN];

	switch ( c ) {
	case 'c':	/* id2children */
		sprintf( name, "id2children" );
		break;
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
		printf( "specify one of [fdeci] to select file\n" );
		return( NULL );
		break;
	}
	if ( fname != NULL ) {
		*fname = name;
	}

	return( openfile( name, MAXPATHLEN, mode, verbose, c ) );
}

static void
print_entry( fp, c, key, klabel, data, dlabel )
    FILE	*fp;
    char	c;
    Datum	*key;
    char	*klabel;
    Datum	*data;
    char	*dlabel;
{
	ID	id;
	IDList	*idl;
	int	i;
	char	msg[2];

	if ( data != NULL && data->dptr == NULL ) {
		msg[0] = c;
		msg[1] = '\0';

		if ( ldbm_errno( dbp ) == 0 )
			perror( msg );
		else
			fprintf( stderr, "%s: db_errno %d\n", msg,
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
			fprintf( fp, "%s%d\n", dlabel ? dlabel : "", id );
		}
		break;

	case 'e':	/* id2entry - key is dnid, data is entry */
		if ( key != NULL ) {
			SAFEMEMCPY( (char *) &id, key->dptr, sizeof(ID) );
			fprintf( fp, "%s %d\n", klabel, id );
		}
		if ( data != NULL ) {
			if ( dlabel ) {
				fprintf( fp, "data length: %d\n", data->dsize );
				fputs( dlabel, fp );
			}
			fputs( data->dptr, fp );
		}
		break;

	case 'c':
	case 'i':	/* index - key is string, data is dnid[] */
		if ( key != NULL )
			fprintf( fp, "%s%s (len %d)\n", klabel, key->dptr,
			    key->dsize );
		if ( data != NULL ) {
			idl = (IDList *) data->dptr;

			if ( dlabel )
				fprintf( fp, "%s\tnmax=%d\n\tncur=%d\n", dlabel,
				    idl->b_nmax, idl->b_nids );

			if ( INDIRECT_BLOCK( idl ) ) {
				for ( i = 0; idl->b_ids[i] != NOID; i++ ) {
					fprintf( fp, "\t%d\n", idl->b_ids[i] );
				}
			} else if ( ALLIDS( idl ) ) {
				fprintf( fp, "\tALLIDS (1..%d)\n",
				    idl->b_nids - 1 );
			} else {
				for ( i = 0; i < idl->b_nids; i++ ) {
					fprintf( fp, "\t%d\n", idl->b_ids[i] );
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
		fprintf( stderr, "specify [deci] to select a file\n" );
		break;
	}
}

static void
get_keydata( fp, c, key, data )
    FILE	*fp;
    char	c;
    Datum	*key;
    Datum	*data;
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
				exit( 0 );
			}
			kbuf[strlen( kbuf ) - 1] = '\0';
			key->dptr = strdup( kbuf );
			key->dsize = strlen( kbuf ) + 1;
		}

		if ( data != NULL ) {
			if ( tty )
				printf( "  dnid: " );
			if ( fgets( dbuf, sizeof(dbuf), fp ) == NULL ) {
				exit( 0 );
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
				exit( 0 );
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

	case 'c':	/* id2children - key is string dnid, data is dnid[] */
	case 'i':	/* index - key is string, data is dnid[] */
		if ( key != NULL ) {
			if ( tty )
				printf( "  key: " );
			if ( fgets( kbuf, sizeof(kbuf), fp ) == NULL ) {
				exit( 0 );
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
		fprintf(stderr, "specify [deci] to select file type\n");
		break;
	}
}


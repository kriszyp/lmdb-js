#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#include <sys/param.h>

#include "ldapconfig.h"
#include "../slap.h"
#include "../back-ldbm/back-ldbm.h"
#include "ldif.h"

#define INDEXCMD		"ldif2index"
#define ID2ENTRYCMD		"ldif2id2entry"
#define ID2CHILDRENCMD		"ldif2id2children"
#define MAXARGS      		100

int		ldap_debug;
int		ldap_syslog;
int		ldap_syslog_level;
int		global_schemacheck;
long		num_entries_sent;
long		num_bytes_sent;
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

static void fork_child( char *prog, char *args[] );
static void	wait4kids( int nkidval );

static char	*indexcmd;
static char	*tailorfile;
static char	*inputfile;
static int      maxkids = 1;
static int      nkids;

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s -i inputfile [-d debuglevel] [-f configfile] [-j #jobs] [-n databasenumber] [-s sbindir]\n", name );
	exit( 1 );
}

int
main( int argc, char **argv )
{
	int		i, stop, status;
	char		*linep, *buf, *sbindir;
	char		*args[10];
	char		buf2[20], buf3[20];
	char		line[BUFSIZ];
	char		cmd[MAXPATHLEN];
	int		lineno, elineno;
	int      	lmax, lcur;
	int		dbnum;
	ID		id;
	Backend		*be = NULL;
	struct berval	bv;
	struct berval	*vals[2];
	Avlnode		*avltypes = NULL;
	extern char	*optarg;

	sbindir = DEFAULT_SBINDIR;
	tailorfile = SLAPD_DEFAULT_CONFIGFILE;
	dbnum = -1;
	while ( (i = getopt( argc, argv, "d:e:s:f:i:j:n:" )) != EOF ) {
		switch ( i ) {
		case 'd':	/* turn on debugging */
			ldap_debug = atoi( optarg );
			break;

		case 's':	/* alternate sbindir (index cmd location) */
		case 'e':	/* accept -e for backwards compatibility */
			sbindir = strdup( optarg );
			break;

		case 'f':	/* specify a tailor file */
			tailorfile = strdup( optarg );
			break;

		case 'i':	/* input file */
			inputfile = strdup( optarg );
			break;

		case 'j':	/* number of parallel index procs */
			maxkids = atoi( optarg );
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

	init();
	read_config( tailorfile, &be, NULL );

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
	be = &backends[dbnum];

	/*
	 * generate the id2entry index
	 */

	i = 0;
	sprintf( cmd, "%s/%s", sbindir, ID2ENTRYCMD );
	args[i++] = cmd;
	args[i++] = "-i";
	args[i++] = inputfile;
	args[i++] = "-f";
	args[i++] = tailorfile;
	args[i++] = "-n";
	sprintf( buf2, "%d", dbnum+1 );
	args[i++] = buf2;
	if ( ldap_debug ) {
		sprintf( buf3, "%d", ldap_debug );
		args[i++] = "-d";
		args[i++] = buf3;
	}
	args[i++] = NULL;
	fork_child( cmd, args );

	/*
	 * generate the dn2id and id2children indexes
	 */

	i = 0;
	sprintf( cmd, "%s/%s", sbindir, ID2CHILDRENCMD );
	args[i++] = cmd;
	args[i++] = "-i";
	args[i++] = inputfile;
	args[i++] = "-f";
	args[i++] = tailorfile;
	args[i++] = "-n";
	sprintf( buf2, "%d", dbnum+1 );
	args[i++] = buf2;
	if ( ldap_debug ) {
		sprintf( buf3, "%d", ldap_debug );
		args[i++] = "-d";
		args[i++] = buf3;
	}
	args[i++] = NULL;
	fork_child( cmd, args );

	/*
	 * generate the attribute indexes
	 */

	i = 0;
	sprintf( cmd, "%s/%s", sbindir, INDEXCMD );
	args[i++] = cmd;
	args[i++] = "-i";
	args[i++] = inputfile;
	args[i++] = "-f";
	args[i++] = tailorfile;
	args[i++] = "-n";
	sprintf( buf2, "%d", dbnum+1 );
	args[i++] = buf2;
	if ( ldap_debug ) {
		sprintf( buf3, "%d", ldap_debug );
		args[i++] = "-d";
		args[i++] = buf3;
	}
	args[i++] = NULL;		/* will hold the attribute name */
	args[i++] = NULL;

	id = 0;
	stop = 0;
	buf = NULL;
	lineno = 0;
	lcur = lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( ! stop ) {
		char		*type, *val, *s;
		int		vlen, indexmask, syntaxmask;
		Datum		key, data;

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
			id++;
			s = buf;
			elineno = 0;
			while ( (linep = str_getline( &s )) != NULL ) {
				elineno++;
				if ( str_parse_line( linep, &type, &val, &vlen )
				    != 0 ) {
					Debug( LDAP_DEBUG_PARSE,
			    "bad line %d in entry ending at line %d ignored\n",
					    elineno, lineno, 0 );
					continue;
				}

				if ( !isascii( *type ) || isdigit( *type ) )
					continue;

				type = strdup( type );
				if ( avl_insert( &avltypes, type, strcasecmp,
				    avl_dup_error ) != 0 ) {
					free( type );
				} else {
					attr_masks( be->be_private, type,
					    &indexmask, &syntaxmask );
					if ( indexmask ) {
						args[i - 2] = type;
						fork_child( cmd, args );
					}
				}
			}
			*buf = '\0';
			lcur = 0;
		}
	}
	(*be->be_close)( be );

	wait4kids( -1 );

	exit( 0 );
}

static void
fork_child( char *prog, char *args[] )
{
	int	status, pid;

	wait4kids( maxkids );

	switch ( pid = fork() ) {
	case 0:		/* child */
		execvp( prog, args );
		fprintf( stderr, "%s: ", prog );
		perror( "execv" );
		exit( -1 );
		break;

	case -1:	/* trouble */
		fprintf( stderr, "Could not fork to run %s\n", prog );
		perror( "fork" );
		break;

	default:	/* parent */
		nkids++;
		break;
	}
}

static void
wait4kids( int nkidval )
{
	int		status;
	unsigned char	*p;

	while ( nkids >= nkidval ) {
		wait( &status );
		p = (unsigned char *) &status;
		if ( p[sizeof(int) - 1] == 0177 ) {
			fprintf( stderr,
			    "stopping: child stopped with signal %d\n",
			    p[sizeof(int) - 2] );
		} else if ( p[sizeof(int) - 1] != 0 ) {
			fprintf( stderr, 
			    "stopping: child terminated with signal %d\n",
			    p[sizeof(int) - 1] );
			exit( p[sizeof(int) - 1] );
		} else if ( p[sizeof(int) - 2] != 0 ) {
			fprintf( stderr, 
			    "stopping: child exited with status %d\n",
			    p[sizeof(int) - 2] );
			exit( p[sizeof(int) - 2] );
		} else {
			nkids--;
		}
	}
}

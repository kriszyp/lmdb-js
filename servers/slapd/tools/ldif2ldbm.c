#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "ldapconfig.h"
#include "../slap.h"
#include "../back-ldbm/back-ldbm.h"
#include "ldif.h"

#define INDEXCMD		"ldif2index" EXEEXT
#define ID2ENTRYCMD		"ldif2id2entry" EXEEXT
#define ID2CHILDRENCMD		"ldif2id2children" EXEEXT

#define MAXARGS      		100

static void fork_child( char *prog, char *args[] );
static void	wait4kids( int nkidval );

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
	int		i, stop;
	char		*linep, *buf, *sbindir;
	char		*args[MAXARGS];
	char		buf2[20], buf3[20];
	char		line[BUFSIZ];
	char		cmd[MAXPATHLEN];
	int		lineno, elineno;
	int      	lmax, lcur;
	int		dbnum;
	ID		id;
	int		rc;
    int     cmdkids = 1;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];
	Avlnode		*avltypes = NULL;

	ldbm_ignore_nextid_file = 1;

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
			cmdkids = atoi( optarg );
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

	rc = slap_init(SLAP_TOOL_MODE, "ldif2ldbm");
	if (rc != 0 ) {
		fprintf( stderr, "ldif2ldbm: slap_init failed!\n");
		exit(1);
	}

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

    maxkids = cmdkids;

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
			while ( (linep = ldif_getline( &s )) != NULL ) {
				elineno++;
				if ( ldif_parse_line( linep, &type, &val, &vlen )
				    != 0 ) {
					Debug( LDAP_DEBUG_PARSE,
			    "bad line %d in entry ending at line %d ignored\n",
					    elineno, lineno, 0 );
					continue;
				}

				if ( !isascii( *type ) || isdigit( *type ) )
					continue;

				type = strdup( type );
				if ( avl_insert( &avltypes, type, (AVL_CMP) strcasecmp,
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

	wait4kids( -1 );

	slap_shutdown(dbnum);

	slap_destroy();

	return( 0 );
}

#ifdef WIN32

static HANDLE processes[MAXIMUM_WAIT_OBJECTS];

static void
fork_child( char *prog, char *args[] )
{
    PROCESS_INFORMATION proc_info;
    PROCESS_INFORMATION *pinfo = &proc_info;
    STARTUPINFO  start_info;
    int i;
    char cmdLine[2048];

    wait4kids( maxkids );

    i = 1;
    memset( &start_info, 0, sizeof(STARTUPINFO) );
    memset( cmdLine, 0, sizeof(cmdLine) );
    strcpy( cmdLine, prog );
    while ( args[i] != NULL )
    {
        strcat( cmdLine, " " );
        strcat( cmdLine, args[i] );
        i++;
    }

    if ( !CreateProcess( NULL, cmdLine, NULL, NULL,
                         TRUE, CREATE_NEW_CONSOLE,
                         NULL, NULL, &start_info, pinfo ) )
    {
        fprintf( stderr, "Could not create %s: ", prog );
        perror( "CreateProcess" );
        exit (-1);
    }

    processes[nkids] = proc_info.hProcess;
    nkids++;

}

static void
wait4kids( int nkidval )
{
    DWORD  wait_index;
    while( nkids >= nkidval )
    {
        wait_index = WaitForMultipleObjects( nkids, processes, FALSE, INFINITE );
        /*
        *  processes[wait_index] completed.  Move any remaining indexes into its
        *  place in the array so it stays filled.
        */
        if ( nkids > 1 )
        {
            memcpy ( &processes[wait_index], &processes[wait_index+1], sizeof(HANDLE)*(nkids-1) );
            processes[nkids] = 0;
        }
        nkids--;
    }
}

#else

static void
fork_child( char *prog, char *args[] )
{
	int	pid;

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

#endif

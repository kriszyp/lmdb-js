#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "ldif2common.h"
#include "../back-bdb2/back-bdb2.h"
#include "ldif.h"

#define INDEXCMD		"ldif2index-bdb2"
#define ID2ENTRYCMD		"ldif2id2entry-bdb2"
#define ID2CHILDRENCMD		"ldif2id2children-bdb2"
#define MAXARGS      		100

static void fork_child( char *prog, char *args[] );
static void	wait4kids( int nkidval );

static int      maxkids = 1;
static int      nkids;

int
main( int argc, char **argv )
{
	int		i, stop;
	char		*linep, *buf;
	char		*args[MAXARGS];
	char		buf2[20], buf3[20];
	char		line[BUFSIZ];
	char		cmd[MAXPATHLEN];
	int		lineno, elineno;
	int      	lmax, lcur;
	ID		id;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];
	Avlnode		*avltypes = NULL;

	slap_ldif_init( argc, argv, LDIF2LDBM, "bdb2", SLAP_TOOL_MODE );

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
		ber_len_t		vlen;
		int indexmask, syntaxmask;

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
					bdb2i_attr_masks( be->be_private, type,
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

	slap_shutdown(dbnum);

	wait4kids( -1 );

	slap_destroy();

	exit( EXIT_SUCCESS );
}

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
		exit( EXIT_FAILURE );
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

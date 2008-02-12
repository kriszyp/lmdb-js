/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Kurt Spanier for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/dirent.h>
#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/wait.h>


#include "ldap_defaults.h"
#include "lutil.h"


#define SEARCHCMD		"slapd-search"
#define READCMD			"slapd-read"
#define ADDCMD			"slapd-addel"
#define MODRDNCMD		"slapd-modrdn"
#define MODIFYCMD		"slapd-modify"
#define MAXARGS      		100
#define MAXREQS			5000
#define LOOPS			"100"
#define RETRIES			"0"

#define TSEARCHFILE		"do_search.0"
#define TREADFILE		"do_read.0"
#define TADDFILE		"do_add."
#define TMODRDNFILE		"do_modrdn.0"
#define TMODIFYFILE		"do_modify.0"

static char *get_file_name( char *dirname, char *filename );
static int  get_search_filters( char *filename, char *filters[], char *bases[] );
static int  get_read_entries( char *filename, char *entries[] );
static void fork_child( char *prog, char **args );
static void	wait4kids( int nkidval );

static int      maxkids = 20;
static int      nkids;

#ifdef HAVE_WINSOCK
static HANDLE	*children;
static char argbuf[BUFSIZ];
#define	ArgDup(x) strdup(strcat(strcat(strcpy(argbuf,"\""),x),"\""))
#else
#define	ArgDup(x) strdup(x)
#endif

static void
usage( char *name )
{
	fprintf( stderr,
		"usage: %s "
		"-H <uri> | ([-h <host>] -p <port>) "
		"-D <manager> "
		"-w <passwd> "
		"-d <datadir> "
		"[-j <maxchild>] "
		"[-l <loops>] "
		"-P <progdir> "
		"[-r <maxretries>] "
		"[-t <delay>] "
		"[-F]\n",
		name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int		i, j;
	char		*uri = NULL;
	char		*host = "localhost";
	char		*port = NULL;
	char		*manager = NULL;
	char		*passwd = NULL;
	char		*dirname = NULL;
	char		*progdir = NULL;
	char		*loops = LOOPS;
	char		*retries = RETRIES;
	char		*delay = "0";
	DIR			*datadir;
	struct dirent	*file;
	char		*sfile = NULL;
	char		*sreqs[MAXREQS];
	char		*sbase[MAXREQS];
	int         snum = 0;
	char		*rfile = NULL;
	char		*rreqs[MAXREQS];
	int         rnum = 0;
	char		*afiles[MAXREQS];
	int         anum = 0;
	char		*mfile = NULL;
	char		*mreqs[MAXREQS];
	int		mnum = 0;
	char		*sargs[MAXARGS];
	int			sanum;
	char		scmd[MAXPATHLEN];
	char		*rargs[MAXARGS];
	int			ranum;
	char		rcmd[MAXPATHLEN];
	char		*aargs[MAXARGS];
	int			aanum;
	char		acmd[MAXPATHLEN];
	char		*margs[MAXARGS];
	int		manum;
	char		mcmd[MAXPATHLEN];
	char		*modargs[MAXARGS];
	int		modanum;
	char		modcmd[MAXPATHLEN];
	char		*modfile = NULL;
	char		*modreqs[MAXREQS];
	char		*moddn[MAXREQS];
	int		modnum = 0;
	int		friendly = 0;

	while ( (i = getopt( argc, argv, "D:d:FH:h:j:l:P:p:r:t:w:" )) != EOF ) {
		switch( i ) {
		case 'D':		/* slapd manager */
			manager = ArgDup( optarg );
			break;

		case 'd':		/* data directory */
			dirname = strdup( optarg );
			break;

		case 'F':
			friendly++;
			break;

		case 'H':		/* slapd uri */
			uri = strdup( optarg );
			break;

		case 'h':		/* slapd host */
			host = strdup( optarg );
			break;

		case 'j':		/* the number of parallel clients */
			if ( lutil_atoi( &maxkids, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'l':		/* the number of loops per client */
			loops = strdup( optarg );
			break;

		case 'P':		/* prog directory */
			progdir = strdup( optarg );
			break;

		case 'p':		/* the servers port number */
			port = strdup( optarg );
			break;

		case 'r':		/* the number of retries in case of error */
			retries = strdup( optarg );
			break;

		case 't':		/* the delay in seconds between each retry */
			delay = strdup( optarg );
			break;

		case 'w':		/* the managers passwd */
			passwd = ArgDup( optarg );
			break;

		default:
			usage( argv[0] );
			break;
		}
	}

	if (( dirname == NULL ) || ( port == NULL && uri == NULL ) ||
			( manager == NULL ) || ( passwd == NULL ) || ( progdir == NULL ))
		usage( argv[0] );

#ifdef HAVE_WINSOCK
	children = malloc( maxkids * sizeof(HANDLE) );
#endif
	/* get the file list */
	if ( ( datadir = opendir( dirname )) == NULL ) {

		fprintf( stderr, "%s: couldn't open data directory \"%s\".\n",
					argv[0], dirname );
		exit( EXIT_FAILURE );

	}

	/*  look for search, read, modrdn, and add/delete files */
	for ( file = readdir( datadir ); file; file = readdir( datadir )) {

		if ( !strcasecmp( file->d_name, TSEARCHFILE )) {
			sfile = get_file_name( dirname, file->d_name );
			continue;
		} else if ( !strcasecmp( file->d_name, TREADFILE )) {
			rfile = get_file_name( dirname, file->d_name );
			continue;
		} else if ( !strcasecmp( file->d_name, TMODRDNFILE )) {
			mfile = get_file_name( dirname, file->d_name );
			continue;
		} else if ( !strcasecmp( file->d_name, TMODIFYFILE )) {
			modfile = get_file_name( dirname, file->d_name );
			continue;
		} else if ( !strncasecmp( file->d_name, TADDFILE, strlen( TADDFILE ))
			&& ( anum < MAXREQS )) {
			afiles[anum++] = get_file_name( dirname, file->d_name );
			continue;
		}
	}

	closedir( datadir );

	/* look for search requests */
	if ( sfile ) {
		snum = get_search_filters( sfile, sreqs, sbase );
	}

	/* look for read requests */
	if ( rfile ) {
		rnum = get_read_entries( rfile, rreqs );
	}

	/* look for modrdn requests */
	if ( mfile ) {
		mnum = get_read_entries( mfile, mreqs );
	}
	/* look for modify requests */
	if ( modfile ) {
		modnum = get_search_filters( modfile, modreqs, moddn );
	}

	/*
	 * generate the search clients
	 */

	sanum = 0;
	snprintf( scmd, sizeof scmd, "%s" LDAP_DIRSEP SEARCHCMD,
		progdir );
	sargs[sanum++] = scmd;
	if ( uri ) {
		sargs[sanum++] = "-H";
		sargs[sanum++] = uri;
	} else {
		sargs[sanum++] = "-h";
		sargs[sanum++] = host;
		sargs[sanum++] = "-p";
		sargs[sanum++] = port;
	}
	sargs[sanum++] = "-D";
	sargs[sanum++] = manager;
	sargs[sanum++] = "-w";
	sargs[sanum++] = passwd;
	sargs[sanum++] = "-l";
	sargs[sanum++] = loops;
	sargs[sanum++] = "-r";
	sargs[sanum++] = retries;
	sargs[sanum++] = "-t";
	sargs[sanum++] = delay;
	sargs[sanum++] = "-b";
	sargs[sanum++] = NULL;		/* will hold the search base */
	sargs[sanum++] = "-f";
	sargs[sanum++] = NULL;		/* will hold the search request */
	sargs[sanum++] = NULL;

	/*
	 * generate the read clients
	 */

	ranum = 0;
	snprintf( rcmd, sizeof rcmd, "%s" LDAP_DIRSEP READCMD,
		progdir );
	rargs[ranum++] = rcmd;
	if ( uri ) {
		rargs[ranum++] = "-H";
		rargs[ranum++] = uri;
	} else {
		rargs[ranum++] = "-h";
		rargs[ranum++] = host;
		rargs[ranum++] = "-p";
		rargs[ranum++] = port;
	}
	rargs[ranum++] = "-l";
	rargs[ranum++] = loops;
	rargs[ranum++] = "-r";
	rargs[ranum++] = retries;
	rargs[ranum++] = "-t";
	rargs[ranum++] = delay;
	rargs[ranum++] = "-e";
	rargs[ranum++] = NULL;		/* will hold the read entry */
	rargs[ranum++] = NULL;

	/*
	 * generate the modrdn clients
	 */

	manum = 0;
	snprintf( mcmd, sizeof mcmd, "%s" LDAP_DIRSEP MODRDNCMD,
		progdir );
	margs[manum++] = mcmd;
	if ( uri ) {
		margs[manum++] = "-H";
		margs[manum++] = uri;
	} else {
		margs[manum++] = "-h";
		margs[manum++] = host;
		margs[manum++] = "-p";
		margs[manum++] = port;
	}
	margs[manum++] = "-D";
	margs[manum++] = manager;
	margs[manum++] = "-w";
	margs[manum++] = passwd;
	margs[manum++] = "-l";
	margs[manum++] = loops;
	margs[manum++] = "-r";
	margs[manum++] = retries;
	margs[manum++] = "-t";
	margs[manum++] = delay;
	if ( friendly ) {
		margs[manum++] = "-F";
	}
	margs[manum++] = "-e";
	margs[manum++] = NULL;		/* will hold the modrdn entry */
	margs[manum++] = NULL;
	
	/*
	 * generate the modify clients
	 */

	modanum = 0;
	snprintf( modcmd, sizeof modcmd, "%s" LDAP_DIRSEP MODIFYCMD,
		progdir );
	modargs[modanum++] = modcmd;
	if ( uri ) {
		modargs[modanum++] = "-H";
		modargs[modanum++] = uri;
	} else {
		modargs[modanum++] = "-h";
		modargs[modanum++] = host;
		modargs[modanum++] = "-p";
		modargs[modanum++] = port;
	}
	modargs[modanum++] = "-D";
	modargs[modanum++] = manager;
	modargs[modanum++] = "-w";
	modargs[modanum++] = passwd;
	modargs[modanum++] = "-l";
	modargs[modanum++] = loops;
	modargs[modanum++] = "-r";
	modargs[modanum++] = retries;
	modargs[modanum++] = "-t";
	modargs[modanum++] = delay;
	if ( friendly ) {
		modargs[modanum++] = "-F";
	}
	modargs[modanum++] = "-e";
	modargs[modanum++] = NULL;		/* will hold the modify entry */
	modargs[modanum++] = "-a";;
	modargs[modanum++] = NULL;		/* will hold the ava */
	modargs[modanum++] = NULL;

	/*
	 * generate the add/delete clients
	 */

	aanum = 0;
	snprintf( acmd, sizeof acmd, "%s" LDAP_DIRSEP ADDCMD,
		progdir );
	aargs[aanum++] = acmd;
	if ( uri ) {
		aargs[aanum++] = "-H";
		aargs[aanum++] = uri;
	} else {
		aargs[aanum++] = "-h";
		aargs[aanum++] = host;
		aargs[aanum++] = "-p";
		aargs[aanum++] = port;
	}
	aargs[aanum++] = "-D";
	aargs[aanum++] = manager;
	aargs[aanum++] = "-w";
	aargs[aanum++] = passwd;
	aargs[aanum++] = "-l";
	aargs[aanum++] = loops;
	aargs[aanum++] = "-r";
	aargs[aanum++] = retries;
	aargs[aanum++] = "-t";
	aargs[aanum++] = delay;
	if ( friendly ) {
		aargs[aanum++] = "-F";
	}
	aargs[aanum++] = "-f";
	aargs[aanum++] = NULL;		/* will hold the add data file */
	aargs[aanum++] = NULL;

	for ( j = 0; j < MAXREQS; j++ ) {

		if ( j < snum ) {

			sargs[sanum - 2] = sreqs[j];
			sargs[sanum - 4] = sbase[j];
			fork_child( scmd, sargs );

		}

		if ( j < rnum ) {

			rargs[ranum - 2] = rreqs[j];
			fork_child( rcmd, rargs );

		}

		if ( j < mnum ) {

			margs[manum - 2] = mreqs[j];
			fork_child( mcmd, margs );

		}
		if ( j < modnum ) {

			modargs[modanum - 4] = moddn[j];
			modargs[modanum - 2] = modreqs[j];
			fork_child( modcmd, modargs );

		}

		if ( j < anum ) {

			aargs[aanum - 2] = afiles[j];
			fork_child( acmd, aargs );

		}

	}

	wait4kids( -1 );

	exit( EXIT_SUCCESS );
}

static char *
get_file_name( char *dirname, char *filename )
{
	char buf[MAXPATHLEN];

	snprintf( buf, sizeof buf, "%s" LDAP_DIRSEP "%s",
		dirname, filename );
	return( strdup( buf ));
}


static int
get_search_filters( char *filename, char *filters[], char *bases[] )
{
	FILE    *fp;
	int     filter = 0;

	if ( (fp = fopen( filename, "r" )) != NULL ) {
		char  line[BUFSIZ];

		while (( filter < MAXREQS ) && ( fgets( line, BUFSIZ, fp ))) {
			char *nl;

			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';
			bases[filter] = ArgDup( line );
			fgets( line, BUFSIZ, fp );
			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';

			filters[filter++] = ArgDup( line );

		}
		fclose( fp );
	}

	return( filter );
}


static int
get_read_entries( char *filename, char *entries[] )
{
	FILE    *fp;
	int     entry = 0;

	if ( (fp = fopen( filename, "r" )) != NULL ) {
		char  line[BUFSIZ];

		while (( entry < MAXREQS ) && ( fgets( line, BUFSIZ, fp ))) {
			char *nl;

			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';
			entries[entry++] = ArgDup( line );

		}
		fclose( fp );
	}

	return( entry );
}

#ifndef HAVE_WINSOCK
static void
fork_child( char *prog, char **args )
{
	pid_t	pid;

	wait4kids( maxkids );

	switch ( pid = fork() ) {
	case 0:		/* child */
#ifdef HAVE_EBCDIC
		/* The __LIBASCII execvp only handles ASCII "prog",
		 * we still need to translate the arg vec ourselves.
		 */
		{ char *arg2[MAXREQS];
		int i;

		for (i=0; args[i]; i++) {
			arg2[i] = ArgDup(args[i]);
			__atoe(arg2[i]);
		}
		arg2[i] = NULL;
		args = arg2; }
#endif
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

	while ( nkids >= nkidval ) {
		wait( &status );

		if ( WIFSTOPPED(status) ) {
			fprintf( stderr,
			    "stopping: child stopped with signal %d\n",
			    (int) WSTOPSIG(status) );

		} else if ( WIFSIGNALED(status) ) {
			fprintf( stderr, 
			    "stopping: child terminated with signal %d%s\n",
			    (int) WTERMSIG(status),
#ifdef WCOREDUMP
				WCOREDUMP(status) ? ", core dumped" : ""
#else
				""
#endif
				);
			exit( WEXITSTATUS(status)  );

		} else if ( WEXITSTATUS(status) != 0 ) {
			fprintf( stderr, 
			    "stopping: child exited with status %d\n",
			    (int) WEXITSTATUS(status) );
			exit( WEXITSTATUS(status) );

		} else {
			nkids--;
		}
	}
}
#else

static void
wait4kids( int nkidval )
{
	int rc, i;

	while ( nkids >= nkidval ) {
		rc = WaitForMultipleObjects( nkids, children, FALSE, INFINITE );
		for ( i=rc - WAIT_OBJECT_0; i<nkids-1; i++)
			children[i] = children[i+1];
		nkids--;
	}
}

static void
fork_child( char *prog, char **args )
{
	int rc;

	wait4kids( maxkids );

	rc = _spawnvp( _P_NOWAIT, prog, args );

	if ( rc == -1 ) {
		fprintf( stderr, "%s: ", prog );
		perror("spawnvp");
	} else {
		children[nkids++] = (HANDLE)rc;
	}
}
#endif

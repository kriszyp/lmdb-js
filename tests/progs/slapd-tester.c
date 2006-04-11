/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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

#include "ldap.h"
#include "slapd-common.h"

#define SEARCHCMD		"slapd-search"
#define READCMD			"slapd-read"
#define ADDCMD			"slapd-addel"
#define MODRDNCMD		"slapd-modrdn"
#define MODIFYCMD		"slapd-modify"
#define BINDCMD			"slapd-bind"
#define MAXARGS      		100
#define MAXREQS			5000
#define LOOPS			100
#define OUTERLOOPS		"1"
#define RETRIES			"0"

#define TSEARCHFILE		"do_search.0"
#define TREADFILE		"do_read.0"
#define TADDFILE		"do_add."
#define TMODRDNFILE		"do_modrdn.0"
#define TMODIFYFILE		"do_modify.0"
#define TBINDFILE		"do_bind.0"

static char *get_file_name( char *dirname, char *filename );
static int  get_search_filters( char *filename, char *filters[], char *attrs[], char *bases[] );
static int  get_read_entries( char *filename, char *entries[], char *filters[] );
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
		"[-L <outerloops>] "
		"-P <progdir> "
		"[-r <maxretries>] "
		"[-t <delay>] "
		"[-F] "
		"[-C]\n",
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
	int		loops = LOOPS;
	char		*outerloops = OUTERLOOPS;
	char		*retries = RETRIES;
	char		*delay = "0";
	DIR		*datadir;
	struct dirent	*file;
	int		friendly = 0;
	int		chaserefs = 0;
	int		noattrs = 0;
	/* search */
	char		*sfile = NULL;
	char		*sreqs[MAXREQS];
	char		*sattrs[MAXREQS];
	char		*sbase[MAXREQS];
	int		snum = 0;
	char		*sargs[MAXARGS];
	int		sanum;
	char		scmd[MAXPATHLEN];
	char		sloops[] = "18446744073709551615UL";
	/* read */
	char		*rfile = NULL;
	char		*rreqs[MAXREQS];
	int		rnum = 0;
	char		*rargs[MAXARGS];
	char		*rflts[MAXREQS];
	int		ranum;
	char		rcmd[MAXPATHLEN];
	char		rloops[] = "18446744073709551615UL";
	/* addel */
	char		*afiles[MAXREQS];
	int		anum = 0;
	char		*aargs[MAXARGS];
	int		aanum;
	char		acmd[MAXPATHLEN];
	char		aloops[] = "18446744073709551615UL";
	/* modrdn */
	char		*mfile = NULL;
	char		*mreqs[MAXREQS];
	int		mnum = 0;
	char		*margs[MAXARGS];
	int		manum;
	char		mcmd[MAXPATHLEN];
	char		mloops[] = "18446744073709551615UL";
	/* modify */
	char		*modfile = NULL;
	char		*modreqs[MAXREQS];
	char		*moddn[MAXREQS];
	int		modnum = 0;
	char		*modargs[MAXARGS];
	int		modanum;
	char		modcmd[MAXPATHLEN];
	char		modloops[] = "18446744073709551615UL";
	/* bind */
	char		*bfile = NULL;
	char		*breqs[MAXREQS];
	char		*bcreds[MAXREQS];
	int		bnum = 0;
	char		*bargs[MAXARGS];
	int		banum;
	char		bcmd[MAXPATHLEN];
	char		bloops[] = "18446744073709551615UL";

	char		*friendlyOpt = NULL;

	tester_init( "slapd-tester" );

	while ( (i = getopt( argc, argv, "ACD:d:FH:h:j:l:L:P:p:r:t:w:" )) != EOF ) {
		switch( i ) {
		case 'A':
			noattrs++;
			break;

		case 'C':
			chaserefs++;
			break;

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
			if ( lutil_atoi( &loops, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'L':		/* the number of outerloops per client */
			outerloops = strdup( optarg );
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
		} else if ( !strcasecmp( file->d_name, TBINDFILE )) {
			bfile = get_file_name( dirname, file->d_name );
			continue;
		}
	}

	closedir( datadir );

	/* look for search requests */
	if ( sfile ) {
		snum = get_search_filters( sfile, sreqs, sattrs, sbase );
	}

	/* look for read requests */
	if ( rfile ) {
		rnum = get_read_entries( rfile, rreqs, rflts );
	}

	/* look for modrdn requests */
	if ( mfile ) {
		mnum = get_read_entries( mfile, mreqs, NULL );
	}

	/* look for modify requests */
	if ( modfile ) {
		modnum = get_search_filters( modfile, modreqs, NULL, moddn );
	}

	/* look for bind requests */
	if ( bfile ) {
		bnum = get_search_filters( bfile, bcreds, NULL, breqs );
	}

	/* setup friendly option */

	switch ( friendly ) {
	case 0:
		break;

	case 1:
		friendlyOpt = "-F";
		break;

	default:
		/* NOTE: right now we don't need it more than twice */
	case 2:
		friendlyOpt = "-FF";
		break;
	}

	snprintf( sloops, sizeof( sloops ), "%d", 10 * loops );
	snprintf( rloops, sizeof( rloops ), "%d", 20 * loops );
	snprintf( aloops, sizeof( aloops ), "%d", loops );
	snprintf( mloops, sizeof( mloops ), "%d", loops );
	snprintf( modloops, sizeof( modloops ), "%d", loops );
	snprintf( bloops, sizeof( bloops ), "%d", 20 * loops );

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
	sargs[sanum++] = sloops;
	sargs[sanum++] = "-L";
	sargs[sanum++] = outerloops;
	sargs[sanum++] = "-r";
	sargs[sanum++] = retries;
	sargs[sanum++] = "-t";
	sargs[sanum++] = delay;
	if ( friendly ) {
		sargs[sanum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		sargs[sanum++] = "-C";
	}
	if ( noattrs ) {
		sargs[sanum++] = "-A";
	}
	sargs[sanum++] = "-b";
	sargs[sanum++] = NULL;		/* will hold the search base */
	sargs[sanum++] = "-f";
	sargs[sanum++] = NULL;		/* will hold the search request */

	sargs[sanum++] = NULL;
	sargs[sanum] = NULL;		/* might hold the "attr" request */

	sargs[sanum + 1] = NULL;

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
	rargs[ranum++] = "-D";
	rargs[ranum++] = manager;
	rargs[ranum++] = "-w";
	rargs[ranum++] = passwd;
	rargs[ranum++] = "-l";
	rargs[ranum++] = rloops;
	rargs[ranum++] = "-L";
	rargs[ranum++] = outerloops;
	rargs[ranum++] = "-r";
	rargs[ranum++] = retries;
	rargs[ranum++] = "-t";
	rargs[ranum++] = delay;
	if ( friendly ) {
		rargs[ranum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		rargs[ranum++] = "-C";
	}
	if ( noattrs ) {
		rargs[ranum++] = "-A";
	}
	rargs[ranum++] = "-e";
	rargs[ranum++] = NULL;		/* will hold the read entry */

	rargs[ranum++] = NULL;
	rargs[ranum] = NULL;		/* might hold the filter arg */

	rargs[ranum + 1] = NULL;

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
	margs[manum++] = mloops;
	margs[manum++] = "-L";
	margs[manum++] = outerloops;
	margs[manum++] = "-r";
	margs[manum++] = retries;
	margs[manum++] = "-t";
	margs[manum++] = delay;
	if ( friendly ) {
		margs[manum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		margs[manum++] = "-C";
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
	modargs[modanum++] = modloops;
	modargs[modanum++] = "-L";
	modargs[modanum++] = outerloops;
	modargs[modanum++] = "-r";
	modargs[modanum++] = retries;
	modargs[modanum++] = "-t";
	modargs[modanum++] = delay;
	if ( friendly ) {
		modargs[modanum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		modargs[modanum++] = "-C";
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
	aargs[aanum++] = aloops;
	aargs[aanum++] = "-L";
	aargs[aanum++] = outerloops;
	aargs[aanum++] = "-r";
	aargs[aanum++] = retries;
	aargs[aanum++] = "-t";
	aargs[aanum++] = delay;
	if ( friendly ) {
		aargs[aanum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		aargs[aanum++] = "-C";
	}
	aargs[aanum++] = "-f";
	aargs[aanum++] = NULL;		/* will hold the add data file */
	aargs[aanum++] = NULL;

	/*
	 * generate the bind clients
	 */

	banum = 0;
	snprintf( bcmd, sizeof bcmd, "%s" LDAP_DIRSEP BINDCMD,
		progdir );
	bargs[banum++] = bcmd;
	bargs[banum++] = "-I";	/* don't init on each bind */
	if ( uri ) {
		bargs[banum++] = "-H";
		bargs[banum++] = uri;
	} else {
		bargs[banum++] = "-h";
		bargs[banum++] = host;
		bargs[banum++] = "-p";
		bargs[banum++] = port;
	}
	bargs[banum++] = "-l";
	bargs[banum++] = bloops;
	bargs[banum++] = "-L";
	bargs[banum++] = outerloops;
#if 0
	bargs[banum++] = "-r";
	bargs[banum++] = retries;
	bargs[banum++] = "-t";
	bargs[banum++] = delay;
#endif
	if ( friendly ) {
		bargs[banum++] = friendlyOpt;
	}
	if ( chaserefs ) {
		bargs[banum++] = "-C";
	}
	bargs[banum++] = "-D";
	bargs[banum++] = NULL;
	bargs[banum++] = "-w";
	bargs[banum++] = NULL;
	bargs[banum++] = NULL;

#define	DOREQ(n,j) ((n) && ((maxkids > (n)) ? ((j) < maxkids ) : ((j) < (n))))

	for ( j = 0; j < MAXREQS; j++ ) {
		if ( DOREQ( snum, j ) ) {
			int	jj = j % snum;

			sargs[sanum - 2] = sreqs[jj];
			sargs[sanum - 4] = sbase[jj];
			if ( sattrs[jj] != NULL ) {
				sargs[sanum - 1] = "-a";
				sargs[sanum] = sattrs[jj];

			} else {
				sargs[sanum - 1] = NULL;
			}
			fork_child( scmd, sargs );
		}

		if ( DOREQ( rnum, j ) ) {
			int	jj = j % rnum;

			rargs[ranum - 2] = rreqs[jj];
			if ( rflts[jj] != NULL ) {
				rargs[ranum - 1] = "-f";
				rargs[ranum] = rflts[jj];

			} else {
				rargs[ranum - 1] = NULL;
			}
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

		if ( DOREQ( bnum, j ) ) {
			int	jj = j % bnum;

			bargs[banum - 4] = breqs[jj];
			bargs[banum - 2] = bcreds[jj];
			fork_child( bcmd, bargs );
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
get_search_filters( char *filename, char *filters[], char *attrs[], char *bases[] )
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

			filters[filter] = ArgDup( line );
			if ( attrs ) {
				if ( filters[filter][0] == '+') {
					char	*sep = strchr( filters[filter], ':' );

					if ( sep != NULL ) {
						attrs[ filter ] = &filters[ filter ][ 1 ];
						sep[ 0 ] = '\0';
						/* NOTE: don't free this! */
						filters[ filter ] = &sep[ 1 ];
					}

				} else {
					attrs[ filter] = NULL;
				}
			}
			filter++;

		}
		fclose( fp );
	}

	return( filter );
}


static int
get_read_entries( char *filename, char *entries[], char *filters[] )
{
	FILE    *fp;
	int     entry = 0;

	if ( (fp = fopen( filename, "r" )) != NULL ) {
		char  line[BUFSIZ];

		while (( entry < MAXREQS ) && ( fgets( line, BUFSIZ, fp ))) {
			char *nl;

			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';
			if ( filters != NULL && line[0] == '+' ) {
				LDAPURLDesc	*lud;

				if ( ldap_url_parse( &line[1], &lud ) != LDAP_URL_SUCCESS ) {
					entry = -1;
					break;
				}

				if ( lud->lud_dn == NULL || lud->lud_dn[ 0 ] == '\0' ) {
					ldap_free_urldesc( lud );
					entry = -1;
					break;
				}

				entries[entry] = ArgDup( lud->lud_dn );

				if ( lud->lud_filter ) {
					filters[entry] = ArgDup( lud->lud_filter );

				} else {
					filters[entry] = ArgDup( "(objectClass=*)" );
				}
				ldap_free_urldesc( lud );

			} else {
				entries[entry] = ArgDup( line );
			}

			entry++;

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
		tester_perror( "execvp", NULL );
		exit( EXIT_FAILURE );
		break;

	case -1:	/* trouble */
		tester_perror( "fork", NULL );
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
		tester_perror( "_spawnvp", NULL );
	} else {
		children[nkids++] = (HANDLE)rc;
	}
}
#endif

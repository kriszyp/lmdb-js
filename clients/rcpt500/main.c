/* $OpenLDAP$ */
/*
 * main.c: for rcpt500 (X.500 email query responder)
 *
 * 16 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/unistd.h>

#include "ldap_defaults.h"
#include "rcpt500.h"

int dosyslog = 0;
#ifdef LDAP_CONNECTIONLESS
int do_cldap = 0;
#endif /* LDAP_CONNECTIONLESS */

int derefaliases = 1;
int sizelimit = RCPT500_SIZELIMIT;
int rdncount = RCPT500_RDNCOUNT;
int ldapport = 0;
char *ldaphost = NULL;
char *searchbase = NULL;
char *dapuser = NULL;
char *filterfile = FILTERFILE;
char *templatefile = TEMPLATEFILE;
static char reply[ MAXSIZE * RCPT500_LISTLIMIT ];


/*
 * functions
 */
static int  read_msg(FILE *fp, struct msginfo *msgp);
static char *read_hdr(FILE *fp, int off, char *buf, int MAXSIZEe, char **ln_p);
static int  send_reply(struct msginfo *msgp, char *body);
static int  find_command(char *text, char **argp);

/*
 * main is invoked by sendmail via the alias file
 * the entire incoming message gets piped to our standard input
 */
int
main( int argc, char **argv )
{
    char		*prog, *usage = "%s [-l] [-U] [-h ldaphost] [-p ldapport] [-b searchbase] [-a] [-z sizelimit] [-u dapuser] [-f filterfile] [-t templatefile] [-c rdncount]\n";
    struct msginfo	msg;
    int			c, errflg;

    *reply = '\0';

    if (( prog = strrchr( argv[ 0 ], '/' )) == NULL ) {
	prog = strdup( argv[ 0 ] );
    } else {
	prog = strdup( prog + 1 );
    }

    errflg = 0;
    while (( c = getopt( argc, argv, "alUh:b:s:z:f:t:p:c:" )) != EOF ) {
	switch( c ) {
	case 'a':
	    derefaliases = 0;
	    break;
	case 'l':
	    dosyslog = 1;
	    break;
	case 'U':
#ifdef LDAP_CONNECTIONLESS
	    do_cldap = 1;
#else /* LDAP_CONNECTIONLESS */
	    fprintf( stderr,
			"Compile with -DLDAP_CONNECTIONLESS for -U support\n" );
#endif /* LDAP_CONNECTIONLESS */
	    break;	
	case 'b':
	    searchbase = optarg;
	    break;
	case 'h':
	    ldaphost = optarg;
	    break;
	case 'p':
	    ldapport = atoi( optarg );
	    break;
	case 'z':
	    sizelimit = atoi( optarg );
	    break;
	case 'u':
	    dapuser = optarg;
	    break;
	case 'f':
	    filterfile = optarg;
	    break;
	case 't':
	    templatefile = optarg;
	    break;
	case 'c':
	    rdncount = atoi( optarg );
	    break;
	default:
	    ++errflg;
	}
    }
    if ( errflg || optind < argc ) {
	fprintf( stderr, usage, prog );
	exit( EXIT_FAILURE );
    }

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

    if ( dosyslog ) {
	/*
	 * if syslogging requested, initialize
	 */
#ifdef LOG_DAEMON
	openlog( prog, OPENLOG_OPTIONS, LOG_DAEMON );
#elif LOG_DEBUG
	openlog( prog, OPENLOG_OPTIONS );
#endif
    }

    if ( read_msg( stdin, &msg ) < 0 ) {
	if ( dosyslog ) {
	    syslog( LOG_INFO, "unparseable message ignored" );
	}
	exit( 0 );	/* so as not to give sendmail an error */
    }

    if ( dosyslog ) {
	syslog( LOG_INFO, "processing command \"%s %s\" from %s",
		( msg.msg_command < 0 ) ? "Unknown" :
		cmds[ msg.msg_command ].cmd_text,
		( msg.msg_arg == NULL ) ? "" : msg.msg_arg, msg.msg_replyto );
    }

    if ( msg.msg_command < 0 ) {
	msg.msg_command = 0;	/* unknown command == help command */
    }

/*
    sprintf( reply, "Your request was interpreted as: %s %s\n\n",
	    cmds[ msg.msg_command ].cmd_text, msg.msg_arg );
*/

    (*cmds[ msg.msg_command ].cmd_handler)( &msg, reply );

    if ( send_reply( &msg, reply ) < 0 ) {
	if ( dosyslog ) {
	    syslog( LOG_INFO, "reply failed: %m" );
	}
	exit( 0 );	/* so as not to give sendmail an error */
    }

    if ( dosyslog ) {
	syslog( LOG_INFO, "reply OK" );
    }

    exit( 0 );
}


static int
read_msg( FILE *fp, struct msginfo *msgp )
{
    char	buf[ MAXSIZE ], *line;
    int		command = -1;

    msgp->msg_replyto = msgp->msg_date = msgp->msg_subject = NULL;

    line = NULL;
    while( 1 ) {
	if ( line == NULL ) {
	    if (( line = fgets( buf, MAXSIZE, fp )) == NULL ) {
		break;
	    }
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove trailing newline */
	}

	if ( *buf == '\0' ) {	/* start of message body */
	    break;
	}
	if ( strncasecmp( buf, "Reply-To:", 9 ) == 0 ) {
	    if ( msgp->msg_replyto != NULL ) {
		free( msgp->msg_replyto );
	    }
	     msgp->msg_replyto = read_hdr( fp, 9, buf, MAXSIZE, &line );
	} else if ( strncasecmp( buf, "From:", 5 ) == 0 &&
		    msgp->msg_replyto == NULL ) {
	     msgp->msg_replyto = read_hdr( fp, 5, buf, MAXSIZE, &line );
	} else if ( strncasecmp( buf, "Date:", 5 ) == 0 ) {
	     msgp->msg_date = read_hdr( fp, 5, buf, MAXSIZE, &line );
	} else if ( strncasecmp( buf, "Message-ID:", 5 ) == 0 ) {
	     msgp->msg_messageid = read_hdr( fp, 11, buf, MAXSIZE, &line );
	} else if ( strncasecmp( buf, "Subject:", 8 ) == 0 ) {
	     if (( msgp->msg_subject =
		    read_hdr( fp, 8, buf, MAXSIZE, &line )) != NULL ) {
		command = find_command( msgp->msg_subject, &msgp->msg_arg );
	    }
	} else {
	    line = NULL;	/* discard current line */
	}
    }

    while ( command < 0 && line != NULL ) {
	/*
	 * read the body of the message, looking for commands
	 */
	if (( line = fgets( buf, MAXSIZE, fp )) != NULL ) {
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove trailing newline */
	    command = find_command( buf, &msgp->msg_arg );
	}
    }

    if ( msgp->msg_replyto == NULL ) {
	return( -1 );
    }

    msgp->msg_command = command;
    return( 0 );
}


static char *
read_hdr( FILE *fp, int offset, char *buf, int MAXSIZEe, char **linep )
{
    char	*hdr;

    for ( hdr = buf + offset; isspace( (unsigned char) *hdr ); ++hdr ) {
	;
    }
    if (( hdr = strdup( hdr )) == NULL ) {
	if ( dosyslog ) {
	    syslog( LOG_ERR, "strdup: %m" );
	}
	exit( EXIT_FAILURE );
    }

    while ( 1 ) {
	*linep = fgets( buf, MAXSIZE, fp );
	buf[ strlen( buf ) - 1 ] = '\0';	/* remove trailing newline */
	if ( *linep == NULL || !isspace( (unsigned char) **linep )) {
	    break;
	}
	if (( hdr = realloc( hdr, strlen( hdr ) +
		    strlen( *linep ) + 3 )) == NULL) {
	    if ( dosyslog ) {
		syslog( LOG_ERR, "realloc: %m" );
	    }
	    exit( EXIT_FAILURE );
	}
	strcat( hdr, "\n" );
	strcat( hdr, *linep );
    }

    return( hdr );
}


static int
send_reply( struct msginfo *msgp, char *body )
{
    char	buf[ MAXSIZE ];
    FILE	*cmdpipe;
    int		rc;
    
    if (( cmdpipe = popen( RCPT500_PIPEMAILCMD, "w" )) == NULL ) {
	if ( dosyslog ) {
	    syslog( LOG_ERR, "popen pipemailcmd failed: %m" );
	}
	return( -1 );
    }

    /*
     * send the headers
     */

    sprintf( buf, "From: %s\n", RCPT500_FROM );
    rc = fwrite( buf, strlen( buf ), 1, cmdpipe );

    if ( rc == 1 ) {
	if ( msgp->msg_subject != NULL ) {
	    sprintf( buf, "Subject: Re: %s\n", msgp->msg_subject );
	} else {
	    sprintf( buf, "Subject: query response\n" );
	}
	rc = fwrite( buf, strlen( buf ), 1, cmdpipe );
    }

    if ( rc == 1 && msgp->msg_date != NULL ) {
	/*
	 * add "In-reply-to:" header
	 */
	if ( msgp->msg_messageid == NULL ) {
	    sprintf( buf, "In-reply-to: Your message of \"%s\"\n",
		    msgp->msg_date );
	} else {
	    sprintf( buf,
		    "In-reply-to: Your message of \"%s\"\n             %s\n",
		    msgp->msg_date, msgp->msg_messageid );
	}
	rc = fwrite( buf, strlen( buf ), 1, cmdpipe );
    }

    if ( rc == 1 ) {
	sprintf( buf, "To: %s\n", msgp->msg_replyto );
	rc = fwrite( buf, strlen( buf ), 1, cmdpipe );
    }

    /*
     * send the header/body separator (blank line)
     */
    if ( rc == 1 ) {
	rc = fwrite( "\n", 1, 1, cmdpipe );
    }

    /*
     * send the body
     */
    if ( rc == 1 ) {
	rc = fwrite( body, strlen( body ), 1, cmdpipe );
    }

    if ( rc != 1 && dosyslog ) {
	syslog( LOG_ERR, "write to binmail failed: %m" );
    }

    if ( pclose( cmdpipe ) < 0 ) {
	if ( dosyslog ) {
	    syslog( LOG_ERR, "pclose binmail failed: %m" );
	}
	return( -1 );
    }

    return( rc == 1 ? 0 : -1 );
}


static int
find_command( char *text, char **argp )
{
    int		i;
    char	*s, *p;
    static char argbuf[ MAXSIZE ];

    p = text;
    for ( s = argbuf; *p != '\0'; ++p ) {
	*s++ = TOLOWER( (unsigned char) *p );
    }
    *s = '\0';

    for ( i = 0; cmds[ i ].cmd_text != NULL; ++i ) {
	if (( s = strstr( argbuf, cmds[ i ].cmd_text )) != NULL
	    && isspace( (unsigned char) s[ strlen( cmds[ i ].cmd_text ) ] )) {
	    strcpy( argbuf, text + (s - argbuf) + strlen( cmds[ i ].cmd_text ));
	    *argp = argbuf;
	    while ( isspace( (unsigned char) **argp )) {
		++(*argp);
	    }
	    return( i );
	}
    }

    return( -1 );
}

/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/ 
*                                                                          *
* server.c...                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - Server-Funktions                 *
*            Based on web500gw.c 1.3 written by Frank Richter, TU Chemmniz *
*            which is based on go500gw by Tim Howes, University of         *
*            Michigan  - All rights reserved                               *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            August 16 1995               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            May 6 1999                 ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: server.c,v 1.6 1999/09/10 15:01:19 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "init_exp.h"
#include "checkclient_exp.h"
#include "server.h"
#include "charray_exp.h"

#if defined( TUE_TEL ) || defined( AMBIXGW )
#include "tueTest_exp.h"
#endif


/**
 **  start_server()
 **
 **    Start the Web-X.500-Server.
 **/

PUBLIC void start_server(glob)
GLOB_STRUCT *glob;
{

    int            s, ns, rc;
    int            tblsize;
    int            pid = getpid();
    fd_set            readfds;
    struct hostent        *hp;
    struct sockaddr_in    from;
    int            fromlen;
    void            wait4child();
    long int       idx;

    glob->stat_slice = time(&glob->stat_slice);
    stat_slice = &glob->stat_slice;
    /* if logging is desired via syslog establish connection to syslogd
       and write first log-message */
    if ( dosyslog ) {

        openlog( glob->myname, LOG_PID | LOG_NOWAIT, dosyslog );
        syslog( LOG_INFO, "initializing" );

    }

    /* set up the socket to listen on */
        /*  the actual port to listen is composed by the base-port
            and the language-offset */
        s = set_socket( glob->webport + atoi(glob->lang) );

        /* arrange to reap children */
        (void) signal( SIGCHLD, wait4child );

    if ( dosyslog )
        syslog (LOG_INFO, "socket: %d", s);

    /*  Read LDAP-filter for search-operations */
    if ( (filtd = ldap_init_getfilter( glob->filterfile )) == NULL ) {
        fprintf(stderr,"Cannot open filter file (%s)\n", glob->filterfile );
        exit( 1 );
    }

/*  ###  Code for the static server ### */

    tblsize = getdtablesize();
    syslog (LOG_INFO, "listening for calls...");

    /*  Initialisation of the Anti-Hack-code */
    srand(pid);
    if (glob->comrefuse) hackTimer();
    bzero((char *) conArr, CARRSIZE * sizeof(int));
    bzero((char *) shadowconArr, CARRSIZE * sizeof(long int));
    bzero((char *) sumconArr, CARRSIZE * sizeof(long int));

#ifdef TUE_TEL
    /* initialisation of dit_config 1st time  */
    if(glob->dit_config) {
        init_dit_config();
    }
#endif

    /* initialisation of ip_refuse 1st time  */
    if(glob->ip_refuse) {
        get_ip_refuse_clients(glob);
    }

    /*  the server runs in an infinite loop !!! */
    for ( ;; ) {

        /*  listen on the server-port for incoming connections */
        FD_ZERO( &readfds );
        FD_SET( s, &readfds );

        if ((rc=select(tblsize,(fd_set *)&readfds,NULL,NULL,0))==-1) {
            if ( debug ) perror( "select" );
            continue;
        } else if ( rc == 0 ) {
            continue;
        }

        if ( ! FD_ISSET( s, &readfds ) )
            continue;


        /*  got connection for the server: get data */
        fromlen = sizeof(from);

		/* increment the counter for total connections */
		glob->svc_cnt++;

        /*  get new file-descriptors for the connection */
        if ( (ns = accept( s, (struct sockaddr *)  &from, &fromlen )) == -1 ) {

            /*  new fd could not be assigned -> log & bye */
            if ( debug ) perror( "accept" );
            if ( dosyslog ) {
                syslog (LOG_INFO,
                    "problem with accept, errno=%d, %s <%08d>",
                    errno, strerror(errno), glob->svc_cnt);
            }
            continue;
        }

        /* get time for performance log */
        gettimeofday(&timestore[0], NULL);

        /*  get client-address via DNS */
        hp = gethostbyaddr( (char *) &(from.sin_addr.s_addr),
            sizeof(from.sin_addr.s_addr), AF_INET );

        /* check ip-address for ip_refuse and bye if matched */
		if ( check_ip_denial( &from, glob ) == NOTOK ) {

			if ( dosyslog )
				syslog( LOG_INFO, "IP-REFUSE: access denied for %s <%08d>",
							inet_ntoa( from.sin_addr ), glob->svc_cnt);

            close (ns);
            continue;

        }

        /* get time for performance log */
        gettimeofday(&timestore[1], NULL);

        /* Anti-Hack-part */

        /*  divide Host-IP-addresses in index-groups and count connection */
        idx = IP_HACK(from.sin_addr.s_addr);
        sumconArr[idx]++;

        /*  count try if already locked and bye */
        if(conArr[idx] < 0) {

            shadowconArr[idx]++;
            close (ns);
            continue;

        }

        /*  if not yet locked and maximum amount of connections is exeeded ->
            lock & message & bye
        */
        if (glob->comrefuse && (++conArr[idx] > glob->comrefuse->maxAccept)){

            if (dosyslog)
                syslog(LOG_INFO,
"connection refused for %s (IDX=%d): %d attempts, %d cycles suspended <%08d>",
                             hp ? hp->h_name : "unknown", idx, conArr[idx],
                             glob->comrefuse->suspendCycle, glob->svc_cnt);

            /*  lock for x timecycles */
            conArr[idx] = glob->comrefuse->suspendCycle;

            /*  bye, bye baby */
            close (ns);
            continue;

        }

        /* END of Anti-Hack-part */

        /*  Log the connection */
        if ( dosyslog ) {
            char msg[BUFSIZ];

            sprintf(msg, "TCP connection from %s (%s,%u)",
                (hp == NULL) ? "unknown" : hp->h_name,
                inet_ntoa( from.sin_addr ), from.sin_port );
            glob->server_connection_msg = strdup(msg);
        }

        if ( debug ) {
            fprintf( stderr, "connection from %s (%s)\n",    
                (hp == NULL) ? "unknown" : hp->h_name,
                inet_ntoa( from.sin_addr ) );
        }

        glob->unknown_host = !hp;
    
        /*  OK, now fork a sub-process performing the further communication
            to the client; the father-process is listening for further
            connections */
        switch( pid = fork() ) {
        case 0:        /* child */

            /*  the connection to the client should last at most OUT_TIME
                thereafter terminate connection */
            signal(SIGALRM, timeoutf);
            alarm(OUT_TIME);

            /*  the s-filedescriptor is not needed any more */
            close( s );

            /*  Serve client-request */
            do_queries( ns, glob , inet_ntoa( from.sin_addr ), from.sin_port, hp);
            break;

        case -1:    /* failed */
            if (dosyslog)
				syslog (LOG_INFO, "%s <%08d>",
					glob->server_connection_msg, glob->svc_cnt);
            perror( "fork" );
            break;

        default:    /* parent */
            /*  the father-process continues listening */
            close( ns );
            if ( debug )
                fprintf( stderr, "forked child %d\n", pid );
            break;
        }
    }
    /* NOT REACHED */
}
/* end of function: start_server */


/**
 **  set_socket()
 **
 **    Initialise socket to listen on and assign dedicated FD
 **/

PRIVATE int set_socket(port)
int port;
{
    int            s, one;
    struct sockaddr_in    addr;

    if ( (s = socket( AF_INET, SOCK_STREAM, 0 )) == -1 ) {
                perror( "socket" );
                exit( 1 );
        }

        /* set option so clients can't keep us from coming back up */
    one = 1;
        if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
        sizeof(one) ) < 0 ) {
                perror( "setsockopt" );
                exit( 1 );
        }

        /* bind to a name */
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons( port );
        if ( bind( s, (struct sockaddr *)  &addr, sizeof(addr) ) ) {
                perror( "bind" );
                exit( 1 );
        }

    /* listen for connections */
        if ( listen( s, 512 ) == -1 ) {
                perror( "listen" );
                exit( 1 );
        }

        if ( debug )
        printf( "web500gw listening on port %d\n", port );

    return( s );
}
/* end of function: set_socket */

/* If a sub-daemon exists, remove from Process list */
PRIVATE void wait4child(arg)
int arg;
{
        int     status;

        if ( debug ) printf( "parent: catching child status\n" );
        while ( wait3( &status, WNOHANG | WUNTRACED, 0 ) > 0 )
                ;       /* NULL */
    (void) signal( SIGCHLD, wait4child );
}
/* end of function: wait4child */

/* set signal-handler for Anti-Hack */
PRIVATE void hackTimer()
{
    static time_t  timer = (time_t) 0;
           time_t  now   = time (&now);

    /* re-read IP-REFUSE file if necessary */
	re_readIPrefuse( globP );

    /* re-read INDEX-URL file if necessary */
	re_read_index_url_rules( globP );

    if (!timer) {

        timer = now + comRefuseP->statCycle;

    }

    signal(SIGALRM, reset_conMem);
    alarm((rand() % comRefuseP->tdiff) + comRefuseP->tmin);

    if (now + comRefuseP->tmin > timer) {

        timer = put_hackStats (NULL, now) + comRefuseP->statCycle;
        *stat_slice  = now;

    }

}
/* end of function: hackTimer */


/* Signal-handler for Anti-Hack-code */
PRIVATE void reset_conMem()
{
    int i;

    hackTimer();

    for(i=0; i< 8192; i++)
        if(conArr[i] >= 0) conArr[i] = 0;
        else {
            if(++conArr[i] == 0){
                if (dosyslog)
                    syslog(LOG_INFO, "connection accept resumed for IDX=%d; \
%u connection attempts during suspension <%08d>", i, shadowconArr[i],
							globP->svc_cnt);
                shadowconArr[i] = 0;
        }
    }

}
/* end of function: reset_conMem */


/*  regular output of the access-statistic */
PUBLIC time_t put_hackStats (fp, now)
FILE   *fp;
time_t  now;
{
    int     i, bereiche;
    int     is_html = (fp != NULL);
    char   *eol = is_html ? "<BR>\n" : "\n";
    unsigned long int gesamt = 0;

    if (!now) now = time (&now);

    if (!fp) fp = fopen (comRefuseP->statFile, "w");

    if (fp) {

        if (is_html) fprintf (fp, "<PRE><BR>\n");

        fprintf (fp, "Access-Statistic TWEB%s", eol);
        fprintf (fp, "======================%s", eol);
        if (comRefuseP) fprintf (fp, "FILE : %s%s", comRefuseP->statFile, eol);
        fprintf (fp, "START: %s%s", format_time (*stat_slice), eol);
        fprintf (fp, "END  : %s%s%s%s", format_time (now), eol, eol, eol);

        for (i = 0, bereiche = 0; i < CARRSIZE; i++) {

            if(sumconArr[i]) {
                fprintf (fp, "IP-IDX %5d: %8lu%s", i, sumconArr[i], eol);
                gesamt += sumconArr[i];
                bereiche++;
            }

        }
    if(bereiche > 1) {
            fprintf (fp, "----------------------%s", eol);
            fprintf (fp, "Total:       %8lu  ( from %d IP-Ranges )%s",
                          gesamt, bereiche, eol);
        }

        if (is_html) {

            fprintf (fp, "</PRE><BR>\n");

        } else {

            bzero((char *) sumconArr, CARRSIZE * sizeof(long int));
            fprintf (fp, "\n");
            fclose (fp);

        }
    }
        
    return (now);

} /* put_hackStats */

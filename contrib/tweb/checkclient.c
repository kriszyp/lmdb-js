/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* checkclient.c                                                            *
*                                                                          *
* Function:..Client-Check-Funktions                                        *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            March 7 1996                 Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            March 19 1999              ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: checkclient.c,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "init_exp.h"
#include "charray_exp.h"
#include "checkclient.h"
#include "regular_exp.h"

PRIVATE int check4access (host, glob)
char *host;
GLOB_STRUCT *glob;
/*
 * check if host ends in a valid domain.
 * return OK if so, NOTOK otherwise
 */
{
    return(
     (glob->allow_string ? checkad(host, glob->comp_allow, glob) : OK) &&
     (glob->deny_string ? !checkad(host, glob->comp_deny, glob) : OK));

}
/* end of function: check4access */


PRIVATE int checkad (host, string, glob)
char *host;
regexp *string;
GLOB_STRUCT *glob;
{
    char nhost[BUFSIZ];

    strcpy(nhost, host ? host : "unknown.xxx");
    return( tweb_regexec( string, nhost ));

}
/* end of function: checkad */

/* Analyse Web-Client-Type / proxy + Log-Message */

PUBLIC void checkwwwclient (fp, ip_addr, ip_port, hp, glob)
FILE *fp;
char *ip_addr;
unsigned int ip_port;
struct hostent *hp;
GLOB_STRUCT *glob;
{
    char in[BUFSIZ];
    char agent[BUFSIZ], via[BUFSIZ];
	char *host = hp ? hp->h_name : "unknown";

	*via = *agent = '\0';

    if(!((glob->grant ? checkad(host, glob->comp_grant, glob) : OK) &&
    (glob->refuse ? !checkad(host, glob->comp_refuse, glob) : OK))){

        if (dosyslog)
			syslog (LOG_INFO, "%s REFUSED <%08d>",
                              glob->server_connection_msg, glob->svc_cnt);
        fflush(fp);
        if (http == 1) PRINT_HTML_HEADER;
        fprintf( fp, HTML_HEAD_TITLE, "ACCESS DENIED", glob->la[100]);
        disp_file(glob, glob->header, fp);
        fprintf(fp, "%s", glob->la[97]);
        disp_file(glob, glob->footer, fp);
        PRINT_HTML_FOOTER;
        close_ldap_connections(glob);
        exit_tweb(0);
    }

    glob->is_proxy = FALSE;
    while(fgets( in, BUFSIZ-1,  fp ) && *trimright(in, WSPACE) ) {
        if(strstr(in, "User-Agent:")){
            strcpy(agent, in);
            if(strstr(str_tolower(in), PROXY_TOKEN1) ||
                strstr(in, PROXY_TOKEN2))
                     glob->is_proxy = TRUE;
        }
        if(strstr(in, "Via:")){
            strcpy(via, in);
            glob->is_proxy = TRUE;
        }
    }
    if (dosyslog){
         char useragent[BUFSIZ];

         sprintf(useragent, "%s  (%s,%u) %s",
                            *agent ?  agent : "User-Agent: unknown",
                            ip_addr, ip_port, via);
         glob->user_agent_msg = strdup(useragent);
    }

    /* check if access is allowed ... */

    glob->allowed = 
        ( hp
          && ((check4access(str_tolower(hp->h_name), glob) == OK))
          && !( glob->no_proxy && glob->is_proxy
                && !charray_inlist(glob->allow_proxy, hp->h_name)
              )
        );
}

/* end of function: checkwwwclient */

PUBLIC void decide_access(glob)
GLOB_STRUCT *glob;
{

    if(!glob->allowed) {
        /*  access from a non allowed computer
            ==> put webdn/webpw on a alternative value (if existant) */
        glob->webdn = glob->webdn2;
        glob->webpw = glob->webpw2;
        glob->noauth = TRUE;

        if (dosyslog) syslog (LOG_INFO, "%s DENIED <%08d>",
                                 glob->server_connection_msg, glob->svc_cnt);

    } else {

        /*  if allowed and not strict: list persons without limits */
        if (!glob->strict) glob->max_person = 0;

        if (dosyslog) syslog (LOG_INFO, "%s ALLOWED <%08d>",
                                 glob->server_connection_msg, glob->svc_cnt);
    }
    if (dosyslog) syslog (LOG_INFO, "%s <%08d>",
							glob->user_agent_msg, glob->svc_cnt);

    /*  non configured max-person means full listing */
    if (!glob->max_person) glob->max_person = 100000;

    /*  if result-lists shall be restricted: configure display of 
        privacy-message */
    glob->legal = glob->legal && (!glob->allowed || glob->strict);

    /*  if browsing should be restricted: configure no_browse-variable */
    glob->no_browse = glob->no_browse &&
            (glob->noauth || glob->strict);

}

/* end of function: decide_access */

/* Read ip_refuse dat_file and build up the data structure */

PUBLIC void get_ip_refuse_clients(glob)
GLOB_STRUCT *glob;
{
	if ( glob->ip_refuse ) {

    	FILE *rfp;
    	char  inLine[BUFSIZ];
		char *inLineP;
		size_t   buflen = REFU_BUFSIZ;
        size_t   curlen = (size_t) 1;

    	if(!(rfp = fopen(glob->ip_refuse->dat_file, "r"))) {
        	return;
    	}

		if ( glob->ip_refuse->refu_str ) free( glob->ip_refuse->refu_str );
		glob->ip_refuse->refu_str = ch_calloc( 1, REFU_BUFSIZ );
		*glob->ip_refuse->refu_str = '&';

    	while(fgets(inLine, BUFSIZ-1, rfp)) {
			int  inLen;

			if ( ( inLineP = strchr( inLine, '#' ) )) *inLineP = '\0';
        	inLineP = trim(inLine, " \t\n");
        	if ( *inLineP == '\0' ) continue;

			inLen = strlen( inLineP );
			if ( !( curlen + inLen + 1 < buflen )) {

				glob->ip_refuse->refu_str =
					ch_realloc( glob->ip_refuse->refu_str,
											buflen + REFU_BUFSIZ );
				buflen += REFU_BUFSIZ;

			}

			sprintf( glob->ip_refuse->refu_str, "%s%s&",
						glob->ip_refuse->refu_str, inLineP );

			curlen += inLen;

    	}
		fclose( rfp );

	}
}  /*  get_ip_refuse_clients  */


/* Routine needed to initialize structure in init.c */

/*  Test the incomming IP address for denial  */

PUBLIC int
check_ip_denial( ip_connection, glob )
struct sockaddr_in   *ip_connection;
GLOB_STRUCT          *glob;
{
    int    res = OK;

	if ( glob->ip_refuse ) {
    	char  ip_address[18];

    	sprintf( ip_address, "&%s&",  inet_ntoa( ip_connection->sin_addr ));
		if ( strstr( glob->ip_refuse->refu_str, ip_address ))
			res = NOTOK;

	}

    return( res );

}  /*  check_ip_denial  */


/* re-read IP-REFUSE file if necessary */

PUBLIC void
re_readIPrefuse( glob )
GLOB_STRUCT   *glob;
{
	static int ip_refuse_reload = 0;

	if ( glob->ip_refuse &&
			!( ++ip_refuse_reload % glob->ip_refuse->rereadcycle )) {
		get_ip_refuse_clients( glob );
	}

}  /*  re_readIPrefuse  */


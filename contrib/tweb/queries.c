/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/ 
*                                                                          *
* queries.c..                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - Server-Functions                 *
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
*            September 13 1999          ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: queries.c,v 1.8 1999/09/13 13:47:47 zrnsk01 Exp $
 *
 */

#include "queries.h"


PUBLIC void do_queries( s, glob , ip_addr, ip_port, hp)
int            s;
GLOB_STRUCT   *glob;
char          *ip_addr;
unsigned int   ip_port;
struct hostent *hp;
{
    char        buf[100*BUFSIZ], *query, *tail;
    int        len;
    FILE        *fp;
    int        rc, tblsize;
    struct timeval    timeout;
    fd_set        readfds;
    LDAP        *ld;
    char tstring[100];

#if OL_LDAPV > 0
	int ldap_opt;
#endif

    /* get time for performance log */
    gettimeofday(&timestore[2], NULL);

    /*  open output-port to waiting client */
    if ( (fp = fdopen( s, "a+")) == NULL ) {
        perror( "fdopen" );
        exit_tweb( 1 );
    }

    tblsize = getdtablesize();
    timeout.tv_sec = glob->timeout;
    timeout.tv_usec = 0;
    FD_ZERO( &readfds );
    FD_SET( fileno( fp ), &readfds );

    time(&glob->nowtime);
    time(&glob->expiretime);
    if(glob->cache_expire) {
        glob->expiretime += glob->cache_expire;
        glob->caching =TRUE;
    }
    free(glob->nowtimestr);
    free(glob->expiretimestr);

    strftime(tstring, 99, GMT_FORMAT, gmtime(&glob->nowtime));
    glob->nowtimestr = strdup(tstring);
    strftime(tstring, 99, GMT_FORMAT2, gmtime(&glob->expiretime));
    glob->expiretimestr = strdup(tstring);

    /*  get client-query out from the system */
    if((rc=select(tblsize,(fd_set *)&readfds,NULL,NULL,&timeout))<=0)
        exit_tweb( 1 );

    if ( fgets( buf, sizeof(buf), fp ) == NULL )
        exit_tweb( 1 );

    /* Analyse Web-Client-Type / proxy + log-message */
    checkwwwclient(fp, ip_addr, ip_port, hp, glob);

    len = strlen( buf );
    if ( debug ) {
        fprintf( stderr, "got %d bytes\n", len );

#if OL_LDAPV > 2
        ber_bprint( buf, len );
#else
        lber_bprint( buf, len );
#endif

    }

    /* strip of white spaces */
    query = trim (buf, WSPACE);

    rewind (fp);


    /*  strip "HTTP" from the end of the request */
    if ((tail = strstr(query, " HTTP")) != NULL || 
            (tail = strstr(query, " http")) != NULL) {
        http = 1;
        *tail = '\0';
    }

    /*  recognize GET/HEAD */
    if (!strncasecmp (query, "get", 3)) {

        request = GET;
        query += 3;

    } else if (!strncasecmp (query, "head", 4)) {

        request = HEAD;
        query += 4;

    } else {

        /*  Error because of neither GET- nor HEAD-request */
        do_error(fp, -2, NOT_IMPLEMENTED, glob);
        /* fprintf(fp, "HTTP/1.0 501 %s<br>", glob->la[5]); */
        rewind(fp);
        exit_tweb( 1 );
    }

        /* strip off leading white space and '/' */
    while ( isspace( *query ) || *query == '/') {
        ++query;
    }


    /*  Now the real request is to be analized and served */

    /* refuse robots if according robots.txt file exists */

    if (!strcasecmp(query, "robots.txt")){
        if (http == 1) PRINT_PLAIN_HEADER;
        disp_file(glob, ROBOTS_TXT_FILE, fp);
        exit_tweb(0);
    }

#ifdef TUE_TEL
    if( glob->ton_urls && *query == cTON) {
        if(!glob->ton_urls->admin)
            glob->allowed = 0;
        if(glob->ton_urls->pass_oc) {
            glob->max_person = 10000;
            glob->no_browse = FALSE;
        }
    }
#endif

    decide_access(glob);

    /* get time for performance log */
    gettimeofday(&timestore[3], NULL);

    /* perform handling of pulldown/form retcodes
                          -> gwswitch-redirect || pass */
    if(*query == cPULLDOWN) {
        if(strstr(query, "http")) {
            /* redirection */
            query += 4;
            hex_decode(query);
            PRINT_REDIRECT_HEADER;
            PRINT_HTML_FOOTER;
            exit_tweb(0);
        } else {
            /* pass */
            query += 7;
            hex_decode(query);
        }
    }

    /* perform handling of buttons/form retcodes
                          -> gwswitch-redirect || pass */
    if(*query == cBUTTON) {
        char *strptr;

        query += 2;
        strptr = strrchr( query, '=' );
        *strptr = '\0';

        if(strstr(query, "http")) {
            /* redirection */
            hex_decode(query);
            PRINT_REDIRECT_HEADER;
            PRINT_HTML_FOOTER;
            exit_tweb(0);
        } else {
            /* pass */
            hex_decode(query);
        }
    }


    /*  1. requests that may be served without DSA */
    switch (*query) {


        /*  display Help-File */
        case cHELP:
            if (dosyslog)
                syslog (LOG_INFO, "working on query: %c (%s,%u) <%08d>",
                                  cHELP, ip_addr, ip_port, glob->svc_cnt);
            if (http == 1) PRINT_HTML_HEADER;
            fprintf(fp, "<HTML><HEAD>");
            disp_file(glob, glob->helpfile, fp);
            PRINT_HTML_FOOTER;
            rewind(fp);
            exit_tweb( 0 );

        /*  request error-explanation */
        case cERROR:
            if (dosyslog)
                syslog (LOG_INFO, "working on query: %c (%s,%u) <%08d>",
                                  cERROR, ip_addr, ip_port, glob->svc_cnt);
/*            fprintf(fp, HTML_HEAD_TITLE, "Errors", glob->la[100]);
*/
            do_error( fp, 0 , 1, glob );
            rewind(fp);
            exit_tweb( 0 );

        /*  RCC: remote configuration control */
        case cCONFIG:
            if (dosyslog)
                syslog (LOG_INFO, "working on query: %c (%s,%u) <%08d>",
                                  cCONFIG, ip_addr, ip_port, glob->svc_cnt);
            if (http == 1) PRINT_HTML_HEADER;
            fprintf(fp, HTML_HEAD_TITLE, "Configuration", glob->la[100]);
            output(fp, glob, TRUE);
            langoutput(fp, glob, TRUE);
            PRINT_HTML_FOOTER;
            rewind(fp);
            exit_tweb(0);

        /* query access-statistic */
        case cSTATS:
            if (dosyslog)
                syslog (LOG_INFO, "working on query: %c (%s,%u) <%08d>",
                                  cSTATS, ip_addr, ip_port, glob->svc_cnt);
            if (http == 1) PRINT_HTML_HEADER;
            fprintf(fp, HTML_HEAD_TITLE, "Statistics", glob->la[100]);
            fprintf(fp,
    "\n<strong>#############STATISTIC-DISPLAY#############</strong><br>\n" );
            fprintf( fp, "\n%s\n\n<p>\n", version );
            (void) put_hackStats (fp, 0);
            PRINT_HTML_FOOTER;
            rewind (fp);
            exit_tweb (0);

    /* NOT REACHED */
    }

    /* with ldap-referral use this host + port + use do_read */
    /* query looks like this: Wldap://host:port/dn */
    if ( *query == cREFERRAL ) {
        char *host, *port, *dn = NULL;

        glob->ldap_referral_mode = 1;
        if ( ( host = strstr( query, "ldap://" ) ) ) {
            host += 7;
            if ( ( port = strchr( host, ':' ) ) ) {
                *port++ = '\0';
                 if ( ( dn = strchr( port, '/' ) ) ) {
                     *dn = '\0';
                     glob->ldapd = strdup ( host );
                     glob->ldapport = atoi ( port );
                     *dn = cREAD;
                     query = dn;
                 }
            }
        }
        if ( !dn )
            exit_tweb( 1 );
    }

    /*  from here on there is needed a connection to the DSA */
    if ( (ld = ldap_open( glob->ldapd, glob->ldapport )) == NULL ) {
        if ( debug ) perror( "ldap_open" );
        do_error( fp, LDAP_SERVER_DOWN, SERVER_ERROR, glob);
        rewind(fp);
        exit_tweb( 1 );
    }

    if(glob->caching_terms)
        trade_cache(fp, ld, query, glob);

    /* performance of STRICT-BASEDN (blind out accesses != BASEDN) */

    if(glob->strict_basedn)
        strict_basednf(fp, ld, query, glob);


    /*  2. queries with binding of the owner */
    switch (*query) {

        /*  request of the modification-formulare */
        case cGETMOD:
            /*  log the request without password */
            hex_decode(query);
            if (dosyslog) {
                char qbuf[BUFSIZ], *qbufp;

                strcpy(qbuf, query);
                if( ( qbufp = strchr(qbuf, '?')) )
                    *qbufp = '\0';
                syslog (LOG_INFO, "working on query: %s (%s,%u) <%08d>",
                                  qbuf, ip_addr, ip_port, glob->svc_cnt);
            }
            rewind(fp);

            /*  follow aliases while searching */
#if OL_LDAPV > 0

			ldap_opt = LDAP_DEREF_ALWAYS;
            ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
            ld->ld_deref = LDAP_DEREF_ALWAYS;
#endif

            if ( !searchaliases )
#if OL_LDAPV > 0

			ldap_opt = LDAP_DEREF_FINDING;
            ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
                     ld->ld_deref = LDAP_DEREF_FINDING;
#endif
    
            /*  send WWW-Formulare with contence of the desired entry
                to the client */
            do_form( ld, fp, ++query, glob);
            ldap_unbind (ld);
            close_ldap_connections(glob);
            rewind(fp);
            exit_tweb (0);

        /*  return of the modification-formulare */
        case cDOMOD:

            /*  log the request in readable form without password if desired */
            if (dosyslog) {

                char qbuf[100*BUFSIZ], *qbufp;

                strcpy(qbuf, query);
                if( ( qbufp = strchr (qbuf, '?')) )
                    *qbufp = '\0';
                hex_decode(qbuf+1);
                syslog (LOG_INFO, "working on query: %s (%s,%u) <%08d>",
                                  qbuf, ip_addr, ip_port, glob->svc_cnt);

            }

            /*  perform modification with the original request */
            do_modify( ld, fp, ++query, glob);
            ldap_unbind (ld);
            close_ldap_connections(glob);
            rewind(fp);
            exit_tweb (0);

    /* NOT REACHED */
    }


    /*  perform all the other requests */

    /*  log the request in readable form first */
    hex_decode(query);
    if (dosyslog)
        syslog (LOG_INFO, "working on query: %s (%s,%u) <%08d>",
               *query ? trimright(query, WSPACE) : "BASEDN", ip_addr, ip_port,
				glob->svc_cnt);

    /*  accesses with resolvation of alias-entries */
#if OL_LDAPV > 0

			ldap_opt = LDAP_DEREF_ALWAYS;
            ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
    ld->ld_deref = LDAP_DEREF_ALWAYS;
#endif

    if ( !searchaliases )
#if OL_LDAPV > 0

			ldap_opt = LDAP_DEREF_FINDING;
            ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
             ld->ld_deref = LDAP_DEREF_FINDING;
#endif
    
    /*  bind to DSA by order of the user as Web-DN
        (DN1 or DN2 was decided at check4access) */

#if OL_LDAPV > 0

    /*  a dummy call as long as socket connections are not settled
     *  with OpenLDAP
     */
    if ( dosyslog )
	    syslog( LOG_INFO, "do_queries(): calling ldap_simple_bind_s()...\n" );

#endif

    if ( (rc=ldap_simple_bind_s( ld, glob->webdn, glob->webpw ))
                                                     != LDAP_SUCCESS ) {
        if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
        do_error( fp, rc, SERVER_ERROR, glob);
        rewind(fp);
        exit_tweb( 1 );
    }

    /*  3. requests to the GW by order of the user */
    switch ( *query++ ) {

        /*  read entry */
        case cREAD:
            do_read( ld, fp, query, 0, glob );
            break;

        /*  display second page */
        case cREADALL:
            do_read( ld, fp, query, 1, glob);
            break;

        /*  search entries */
        case cSEARCH:
            do_search( ld, fp, query, glob );
            break;

        /*  list entries (browsing) */
        case cLIST:
            do_menu( ld, fp, query, "", glob );
            break;

#ifdef TUE_TEL
        /*  list entries (browsing TON instead of DN) */
        case cTON:
            if(glob->ton_urls)
                do_ton( ld, fp, query, glob );
            break;
#endif

        /*  request GIF-photo (Photo in X.500 as JPEG) */
        case cGIF:
            do_pict( ld, fp, query, 1, glob);
            break;

        /*  display JPEG-Photo */
        case cJPEG:
            do_pict( ld, fp, query, 2, glob);
            break;

        /*  display X.500-G3FAX-Photo */
        case cG3FAX:
            do_pict( ld, fp, query, 0, glob);
            break;

        /*  play Audio-attribute */
        case cAUDIO:
            do_audio( ld, fp, query, 0, glob);
            break;

        /*  eXtended query format */
        case cEXTENDED:
            do_xtend( ld, fp, query, 0, glob);
            break;

        /*  Default (empty query) is browsing of BASEDN */
        default:
            do_menu( ld, fp, glob->basedn->dn, "", glob );
            break;
    }

    /*  Job done, terminate connection to the DSA and bye! */
    ldap_unbind (ld);
    close_ldap_connections(glob);
    rewind(fp);
    exit_tweb( 0 );
    /* NOT REACHED */
}
/* end of function: do_queries */

PUBLIC void timeoutf(sig)
int sig;
{
    /* fprintf(stderr, "timeout!"); */
    exit_tweb(0);
}
/* end of function: timeoutf */


PRIVATE void strict_basednf(fp, ld, query, glob)
FILE *fp;
LDAP *ld;
char *query;
GLOB_STRUCT   *glob;
{
    char dnbuf[BUFSIZ], basednbuf[BUFSIZ], *strptr;
    LDAPMessage *res, *e;
    int rc, flag = 0, i, j;
    struct timeval timeout;
    char *url = NULL, **uri, *urlnola = NULL;
    pGW_SWITCH_LINE gw_ptr;
    char  *url_tmp;
    char **dnarray, **bdnarray;

#ifdef TUE_TEL
    /* Patch for TONS */
    if( glob->ton_urls && (*query == cTON))
        return;
#endif

    /* Patch for FORMs/PULLDOWNs (cPULLDOWN) */
    if( glob->pull_down_menus && (*query == cPULLDOWN))
        return;

    /* Patch for FORMs/BUTTONs (cBUTTONs) */
    if( glob->pull_down_menus && (*query == cBUTTON))
        return;

    if(*query)
        strcpy(dnbuf, query+1);
    else
        strcpy(dnbuf, "\0");
    hex_decode(dnbuf);
    strcpy(basednbuf, glob->basedn->dn);

    if( ( strptr = strchr(dnbuf, '?')) )
        *strptr = '\0';

    if( *query && !dn_issuffix( dn_normalize(dnbuf), dn_normalize(basednbuf))) {

        dnarray = dn2charray(dnbuf);
        bdnarray = glob->basedn->dnarray;

        strcpy(dnbuf, "\0");
        if (glob->gw_switch) {
            for(gw_ptr = glob->gw_switch->list;
                              !flag && gw_ptr; gw_ptr = gw_ptr->next) {
                if (!dn_cmp ("root", gw_ptr->dn)) {
                    flag = 1;
                    url = gw_ptr->url;
                }
            }
        }
        if(!flag) {
            fprintf(stderr, "Fehler:strict_basedn w/o root-switch!!!!\n");
            exit_tweb(0);
        }

        for(j=0; bdnarray[j] && dnarray[j]; j++) {
            char *dnbufb;

            flag = 0;

            dnbufb = strdup(dnbuf);
            sprintf(dnbuf, "%s%s%s", dnarray[j], *dnbuf ? "," : "" , dnbufb);

            if ( glob->gw_switch && glob->gw_switch->dynamic) {

                if ( (rc=ldap_simple_bind_s( ld, glob->webdn, glob->webpw ))
                                                         != LDAP_SUCCESS ) {
                    if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
                    do_error( fp, rc, SERVER_ERROR, glob);
                    rewind(fp);
                    exit_tweb( 1 );
                }

                timeout.tv_sec = glob->timeout;
                timeout.tv_usec = 0;

                if ( (rc = ldap_search_st( ld, dnbuf, LDAP_SCOPE_BASE, "objectClass=*",
                    NULL, 0, &timeout, &res )) != LDAP_SUCCESS ) {
/*                    do_error(fp, rc, NOT_FOUND, glob);
*/
                    continue;
                }


                if ( (e = ldap_first_entry( ld, res )) == NULL ) {
                    do_error(fp, -2, SERVER_ERROR, glob);
                    return;
                }


                uri = ldap_get_values( ld, e, "labeledURI" );
                for(i=0; uri && uri[i] && *uri[i]; i++) {
                    char *sp;

                    if( ( sp = strchr(uri[i], ' ')) ) {
                        *sp++ = '\0';
                        if(strstr(sp, glob->gw_switch->lagws)) {
                            flag = 1;
                            url = uri[i];
                            break;
                        } else if(strstr(sp, GWS))
                            urlnola = uri[i];
                    }
                }
            }
            if(!flag && urlnola) {
                url = urlnola;
                flag = 1;
            }
            if (glob->gw_switch) {

                for(gw_ptr = glob->gw_switch->list;
                                  !flag && gw_ptr; gw_ptr = gw_ptr->next) {
                    if (!dn_cmp (dnbuf, gw_ptr->dn)) {
                        flag = 1;
                        url = gw_ptr->url;
                    }
                }
            }
            if(strcmp(bdnarray[j], dnarray[j]))
                break;
        }

        if (http == 1) PRINT_HTML_HEADER;
        fprintf( fp, HTML_HEAD_TITLE, "ACCESS DENIED", glob->la[100]);
        disp_file(glob, glob->header, fp);
        fprintf( fp, "%s\n", glob->la[96]);
        url_tmp = strdup(url_complete(url, query, ""));
        fprintf( fp, "<P><A HREF=\"%s\"><b>%s</b></A>\n",
           url_tmp, url_tmp);
        disp_file(glob, glob->footer, fp);
        PRINT_HTML_FOOTER;
        ldap_unbind (ld);
        close_ldap_connections(glob);
        exit_tweb(0);
    }
}
/* end of function: strict_basednf */

PRIVATE void trade_cache(fp, ld, query, glob)
FILE *fp;
LDAP *ld;
char *query;
GLOB_STRUCT   *glob;
{
    pCACHING_TERMS_LINE ca_ptr;
    char dnbuf[BUFSIZ], rdn[BUFSIZ], *strptr;
    char tstring[100];
    int resflag;
    int rc;
    struct timeval timeout;
    LDAPMessage *res, *e;
    char **vals = NULL;

    resflag = 0;
    if(*query)
        strcpy(dnbuf, query+1);
    else
        strcpy(dnbuf, glob->basedn->dn);
    hex_decode(dnbuf);
    if( ( strptr = strchr(dnbuf, '?')) )
        *strptr = '\0';
    strcpy(rdn, dnbuf);
    if( ( strptr = strQuoteChr(rdn, ',')) )
        *strptr = '\0';

    for(ca_ptr = glob->caching_terms; ca_ptr; ca_ptr = ca_ptr->next) {
        if((toupper(*query) == toupper(*ca_ptr->access_type)) ||
            ( !*query && (toupper(*ca_ptr->access_type) == 'M'))) {
            
            if(ca_ptr->rdn_oc && (strstr(str_tolower(rdn), ca_ptr->pattern) ||
                                 (*ca_ptr->pattern == '*'))) {
                time(&glob->expiretime);
                glob->expiretime += ca_ptr->time;
                free(glob->expiretimestr);
                strftime(tstring, 99, GMT_FORMAT2, gmtime(&glob->expiretime));
                glob->expiretimestr = strdup(tstring);
                glob->caching = TRUE;
            }
            if(!ca_ptr->rdn_oc) {
                if(!resflag) {

                    if ( (rc=ldap_simple_bind_s( ld, glob->webdn, glob->webpw ))
                                                         != LDAP_SUCCESS ) {
                        if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
                            do_error( fp, rc, SERVER_ERROR, glob);
                        rewind(fp);
                        exit_tweb( 1 );
                    }

                    timeout.tv_sec = glob->timeout;
                    timeout.tv_usec = 0;

                    if ( (rc = ldap_search_st( ld, dnbuf, LDAP_SCOPE_BASE, "objectClass=*",
                        NULL, 0, &timeout, &res )) != LDAP_SUCCESS ) {
                        do_error(fp, rc, NOT_FOUND, glob);
                        return;
                    }


                    if ( (e = ldap_first_entry( ld, res )) == NULL ) {
                        do_error(fp, -2, SERVER_ERROR, glob);
                        return;
                    }


                    vals = ldap_get_values( ld, e, "objectClass" );
                    resflag = 1;
                }
                if(charray_inlist( vals, ca_ptr->pattern )) {
                    time(&glob->expiretime);
                    glob->expiretime += ca_ptr->time;
                    free(glob->expiretimestr);
                    strftime(tstring, 99, GMT_FORMAT2, gmtime(&glob->expiretime));
                    glob->expiretimestr = strdup(tstring);
                    glob->caching = TRUE;
                }
            }

        }
    }

}
/* end of function: trade_cache */

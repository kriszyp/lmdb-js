/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* x500.c.....                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - X.500-Access-Routines            *
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
*            September 13 1999          ZZZZZ  DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: x500.c,v 1.10 1999/09/13 13:47:48 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "x500.h"
#include "init_exp.h"
#include "support_exp.h"
#include "html_exp.h"

#ifdef TUE_TEL
#include "tueTel_exp.h"
#endif

#if defined( TUE_TEL ) || defined( AMBIXGW )
#include "resort_exp.h"
#endif


PRIVATE int compare(a,b)
DNLIST **a, **b;
{
        return strcmp((*a)->string,(*b)->string);
}
/* end of function: compare */


PRIVATE char * pick_oc(oclist)
char **oclist;
{
    int    i;

    if ( oclist == NULL )
        return( "unknown" );

    for ( i = 0; oclist[i] != NULL; i++ ) {
        if ( strcasecmp( oclist[i], "top" ) != 0 &&
            strcasecmp( oclist[i], "quipuObject" ) != 0 &&
            strcasecmp( oclist[i], "quipuNonLeafObject" ) != 0 )
            return( str_tolower (oclist[i]) );
    }

    return( "unknown" );
}
/* end of function: pick_oc */


PUBLIC char * make_oc_to_string(oc)
char **oc;
{
    static char oc_res[BUFSIZ];
    int i;

    if(!oc) return(NULL);

    *oc_res = '|';
    *(oc_res+1) = '\0';
    for(i = 0; oc[i] && *oc[i]; i++) {
        sprintf(oc_res, "%s%s|", oc_res, oc[i]);
    }
    return(str_tolower (oc_res));
}
/* end of function: make_oc_to_string */


PUBLIC void do_xtend(ld, fp, query, filter, glob)
LDAP *ld;
FILE *fp;
char *query;
char *filter;
GLOB_STRUCT *glob;
{
    char *strptr, dn[BUFSIZ], command[BUFSIZ], extension[BUFSIZ];

    strptr = strchr(query, '?');
    *strptr++ = '\0';
    strcpy(dn, query);
    strcpy(command, strptr);
    if( ( strptr = strchr(command, '#')) ) {
        *strptr++ = '\0';
        strcpy(extension, strptr);
    }
    
    if(!strcasecmp(command, "MENU")){
        glob->tables_marker = strdup(extension);
        do_menu(ld, fp, dn, "", glob);
    }
    
#ifdef TUE_TEL
    if(!strcasecmp(command, "PHONEBOOK")){
        do_phonebook(ld, fp, strstr(dn, "ou=TELEFONBUCH") ? dn
                             : NULL, extension, glob, 1);
    }
#endif

}
/* end of function: do_xtend */

PUBLIC void do_menu(ld, fp, dn, filter, glob)
LDAP *ld;
FILE *fp;
char *dn;
char *filter;
GLOB_STRUCT *glob;
{
    int             rc;
    LDAPMessage     *pres;
    struct timeval  timeout;
    static char     *sattrs[] = { "objectClass", "labeledURI",
                                     "aliasedObjectName", "mail",
                                     "cn", "telephonenumber",
#ifdef TUE_TEL
                                     "tat_ton", "tat_refphone",
#endif
                                     0 };
    static char **attrs = NULL;
    int counter = 0;
    pSEARCH_ONLY_LINE so_ptr;
    char        la_url[BUFSIZ];
    int count;
    char           *ufn;

#if OL_LDAPV > 0
	int         ldap_opt;
#endif

    if(!attrs)
        attrs = (char**) charray_dup(sattrs);

    charray_merge(&attrs, glob->sort_attribs);

    if(glob->raw_data)
        charray_merge(&attrs, glob->raw_attrs);

    for(so_ptr = glob->search_only; so_ptr; so_ptr = so_ptr->next) {
        if (dn_cmp(dn, so_ptr->dn) == 0) {
            break;
        }
    }

    if(!so_ptr) {

        timeout.tv_sec = glob->timeout;
        timeout.tv_usec = 0;

#if OL_LDAPV > 0

		ldap_opt = LDAP_DEREF_FINDING;
        ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
        ld->ld_deref = LDAP_DEREF_FINDING;
#endif

        if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_ONELEVEL,
            glob->menu_filter, attrs, 0, &timeout, &pres )) != LDAP_SUCCESS
            && rc != LDAP_SIZELIMIT_EXCEEDED 
                && rc != LDAP_INSUFFICIENT_ACCESS ) {
            do_error(fp, rc, NOT_FOUND, glob);
            return;
        }

        if (rc == LDAP_SIZELIMIT_EXCEEDED) glob->persRestricted = TRUE;

#if OL_LDAPV > 0

		ldap_opt = LDAP_DEREF_ALWAYS;
        ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
        ld->ld_deref = LDAP_DEREF_ALWAYS;
#endif

        if ((count = (ldap_count_entries(ld, pres) )) < 1) {
            ldap_msgfree (pres);
            do_read (ld, fp, dn, 0, glob);
            return;
        }
        items_displayed = count;
    }

    if (http == 1) {
        PRINT_HTML_HEADER;
    }
    if (request == HEAD) {
        fflush(fp);
        exit_tweb (1);
    }
    fprintf( fp, HTML_HEAD_TITLE, ufn = friendly_dn(dn, glob), glob->la[100]);
    if ( ufn ) free( ufn );

    if (dn_cmp(dn, glob->basedn->dn) == 0)
        disp_file(glob, glob->basedn->head, fp);
    else if(so_ptr && so_ptr->head)
        disp_file(glob, so_ptr->head, fp);
    else
        disp_file(glob, glob->header, fp);

#ifdef TUE_TEL
    fprintf (fp, "\n<A NAME=\"phonebook=Telefonbuch\"></A>\n");
    fprintf (fp, "\n<A NAME=\"phonebook\"></A>\n");
#endif

    make_la_buttons("M", fp, ld, dn, la_url, glob );

    make_header( fp, dn, 0, glob);

    print_rdn(fp, dn, glob);

    make_search_box(fp, ld, dn, glob);

#ifdef AMBIXGW
    /* Button leading to cgi-script */
    if( glob->form_button && !glob->selbsteintrag[0]){
        char  **oc;
        LDAPMessage    *res;
        struct timeval    timeout;
        static char    *attrs[] = { "objectClass", 0 };

        timeout.tv_sec = glob->timeout;
        timeout.tv_usec = 0;
        if ( ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
            attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
            exit_tweb( 1 );
        }
        oc = ldap_get_values( ld, ldap_first_entry( ld, res ), "objectClass" );

        disp_form_button(0, oc, dn, ld, fp, glob);
    }

    /* check to see if selfinsert-buttons are appropriate here */
    if(glob->selbsteintrag[0])
        self_insert(ld,fp,dn,glob);
#endif

#ifdef TUE_TEL
    /* Named link to skip header */
    fprintf (fp, "\n<A NAME=\"pure-data\"></A>\n");
#endif

    fprintf(fp, glob->la[101]);


    if(!so_ptr) {

        /*  DO_MENU  */
        counter = sort_result( ld, pres, dn, glob);

        /* get time for performance log */
        gettimeofday(&timestore[4], NULL);

        list_output(fp, glob);

        if ( ldap_result2error( ld, pres, 1 ) == LDAP_SIZELIMIT_EXCEEDED
            || glob->restricted )
            do_sizelimit(fp, 1, glob);

        if(glob->legal && !glob->legal_top)
            fprintf (fp, "%s\n%s\n", glob->la[101],
                            glob->is_proxy ? glob->la[104] : glob->la[65]);
    }

    if (dn_cmp(dn,glob->basedn->dn) == 0)
        disp_file(glob, glob->basedn->foot, fp);
    else if(so_ptr && so_ptr->foot)
        disp_file(glob, so_ptr->foot, fp);
    else
        disp_file(glob, glob->footer, fp);

    PRINT_HTML_FOOTER;
}
/* end of function: do_menu */


PRIVATE int make_scope(ld, dn, glob)
LDAP *ld;
char *dn;
GLOB_STRUCT *glob;
{
    int        scope, idx;
    char        **oc;
    LDAPMessage    *res;
    struct timeval    timeout;
    static char    *attrs[] = { "objectClass", 0 };

    if ( strcmp( dn, "" ) == 0 )
        return( LDAP_SCOPE_ONELEVEL );

    timeout.tv_sec = glob->timeout;
    timeout.tv_usec = 0;
    if ( ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
        attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
        return( -1 );
    }

    oc = ldap_get_values( ld, ldap_first_entry( ld, res ), "objectClass" );

    /* set scope according to configured object-classes */
    scope = LDAP_SCOPE_ONELEVEL;
    for(idx = 0; glob->subtree_search && glob->subtree_search[idx]; idx++)
        if( charray_inlist( oc, glob->subtree_search[idx]))
            scope = LDAP_SCOPE_SUBTREE;

    ldap_value_free( oc );
    ldap_msgfree( res );

    return( scope );
}
/* end of function: make_scope */

PUBLIC int do_search(ld, fp, query, glob)
LDAP *ld;
FILE *fp;
char *query;
GLOB_STRUCT *glob;
{
    int        scope;
    char        *base, *filter, *strptr;
    char        *filtertype;
    int        count = 0, rc;
    struct timeval    timeout;
    LDAPFiltInfo    *fi;
    LDAPMessage    *e, *res = NULL;
    static char    *attrs[] = { "objectClass", "cn", "sn", "labeledURI", 
                                 "aliasedObjectName", 0 };
    int        counter = 0;
    char               *ufn;
    char title[BUFSIZ], title2[BUFSIZ];

#if OL_LDAPV > 0
	int         ldap_opt;
#endif

    glob->no_browse = FALSE;
    
/* query string: base-DN?[OS]=filter 
 *     search onelevel <--||--> search subtree 
 */
    if ( (filter = strchr( query, '?' )) == NULL ) {
        explain_error( fp, glob->la[89], BAD_REQUEST, glob );
        exit_tweb( 1 );
    }
    *filter++ = '\0';
    if (*filter == '\0' || *(filter+1) != '=') {
        explain_error( fp, glob->la[90], BAD_REQUEST, glob);
        exit_tweb( 1 );
    }
    if( ( strptr = strchr(filter, '&')) )
        *strptr = '\0';
    if( ( strptr = strchr(filter, '*')) )
        *strptr = '\0';
    if (*filter == 'S') {
        scope = LDAP_SCOPE_SUBTREE;
    } else {
        scope = LDAP_SCOPE_ONELEVEL;
    }
    filter += 2;
    if (*filter == '\0') {
        explain_error( fp, glob->la[92], BAD_REQUEST, glob);
        exit_tweb( 1 );
    }
    /* deutsche Umlaute plaetten */
    filter = flatten_chars(filter);

    base = query;

    filtertype = (scope == LDAP_SCOPE_ONELEVEL ? "web500gw onelevel" :
        "web500gw subtree");

#if OL_LDAPV > 0

		ldap_opt = ( scope == LDAP_SCOPE_ONELEVEL ? LDAP_DEREF_FINDING :
						 LDAP_DEREF_ALWAYS );
        ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
    ld->ld_deref = (scope == LDAP_SCOPE_ONELEVEL ? LDAP_DEREF_FINDING :
                                                  LDAP_DEREF_ALWAYS);
#endif

    timeout.tv_sec = glob->timeout;
    timeout.tv_usec = 0;

    for (fi=ldap_getfirstfilter( filtd, filtertype, filter ); fi != NULL;
        fi = ldap_getnextfilter( filtd ) ) {
        if ( (rc = ldap_search_st( ld, base, scope, fi->lfi_filter,
            attrs, 0, &timeout, &res )) != LDAP_SUCCESS
            && rc != LDAP_SIZELIMIT_EXCEEDED ) {

            if (dosyslog) {

#if OL_LDAPV > 0

                int ld_errno;

                ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);
                syslog (LOG_INFO, "ldap_search_st(): %s",
                    ldap_err2string ( ld_errno ));

#else
                syslog (LOG_INFO, "ldap_search_st(): %s",
                    ldap_err2string (ld->ld_errno));
#endif

            }

            do_error(fp, rc, NOT_FOUND, glob);
            return( 1 );
        }

        if ( res && (count = ldap_count_entries( ld, res )) != 0 ) {

            break;
        }

    }
    items_displayed = count;

#if OL_LDAPV > 0

		ldap_opt = LDAP_DEREF_ALWAYS;
        ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
    ld->ld_deref = LDAP_DEREF_ALWAYS;
#endif

    if ( count == 0 ) {

        if (http == 1) {
            fprintf(fp, "HTTP/1.0 404 %s \n", glob->la[6]); 
                        fprintf(fp, "MIME-Version: 1.0\n");
                        fprintf(fp, "Content-Type: text/html\n\n");
        }

        if (request == HEAD) {
            fflush(fp);
            exit_tweb (1);
        }    

        sprintf( title, "%s %s", filter, glob->la[36]);
        fprintf( fp, HTML_HEAD_TITLE, title, glob->la[100]);

        disp_file(glob, glob->header, fp);

        fprintf( fp,
 "<H2>%s</H2> %s <STRONG>%s</STRONG> in <STRONG>%s</STRONG></BODY></HTML>\n\n",
                     glob->la[37], glob->la[38], filter, 
                     (strlen(base) == 0) ? glob->la[77] : ldap_dn2ufn(base));
                fflush(fp);
        return( 0 );
    }
    else if ( count == 1 ) {
        e = ldap_first_entry( ld, res );
        if ( e != NULL ) {
            char *dn, **oc;
            oc = ldap_get_values(ld, e, "objectClass");
            dn = ldap_get_dn(ld, e);
            if ( dn ) {

                /* GW-Switch if one search-result and dyn-URL by
                   PRINT_REDIRECT_HEADER */
        if ( glob->gw_switch->dynamic) {
                    char **uri, query[10*BUFSIZ];
                    int j;

                    uri = ldap_get_values( ld, e, "labeledURI" );
                    for(j=0; uri && uri[j] && *uri[j]; j++) {
                        char *sp;

                        if( ( sp = strchr(uri[j], ' ')) ) {
                            *sp++ = '\0';
                            if(strstr(sp, glob->gw_switch->lagws)) {
                                /*sprintf(query, "%s/M%s", uri[j], dn);*/
                                strcpy(query, uri[j]);
                                hex_decode(query);
                                PRINT_REDIRECT_HEADER;
                                PRINT_HTML_FOOTER;
                                exit_tweb(0);
                            }
                        }
                    }
                }
                /* By default on one result: */
                do_menu(ld, fp, dn, "", glob);
                return (0);
            }
        }
    }

    if (http == 1)
        PRINT_HTML_HEADER;
    if (request == HEAD) {
        fflush(fp);
        exit_tweb (1); 
        }

    sprintf( title2, "%s %s", glob->la[39], filter);
    fprintf( fp, HTML_HEAD_TITLE, title2, glob->la[100]);

    disp_file(glob, glob->header, fp);

    ufn = friendly_dn(base, glob);
    fprintf( fp, "%s <STRONG>\"%s\"</STRONG> in <STRONG>\"%s\"</STRONG> ",
                 glob->la[40], filter, ufn );
    if ( ufn ) free( ufn );

    if(!glob->noauth)
        fprintf( fp, "(%d %s)<br>", count, 
                         count == 1 ? glob->la[70] : glob->la[71]);

      /*  DO_SEARCH  */
      counter = sort_result( ld, res, base, glob);

      /* get time for performance log */
      gettimeofday(&timestore[4], NULL);

     list_output(fp, glob);

    if ( ldap_result2error( ld, res, 1 ) == LDAP_SIZELIMIT_EXCEEDED )
        do_sizelimit(fp, 0, glob);

    if(glob->legal && !glob->legal_top)
        fprintf (fp, "%s\n%s\n", glob->la[101],
                            glob->is_proxy ? glob->la[104] : glob->la[65]);
    
    disp_file(glob, glob->footer, fp);

    PRINT_HTML_FOOTER;

    return( 0 );

}
/* end of function: do_search */


PRIVATE pDISPLAY
find_dPtr( displayList, displayType )
pDISPLAY   displayList;
char      *displayType;
{
    pDISPLAY  dis;

    for ( dis = displayList; dis; dis = dis->next ) {

        if ( !strcasecmp( dis->ocs, displayType )) return( dis );

    }

    return( NULL );

}  /*  find_dPtr  */


PUBLIC void do_read(ld, fp, dn, amore, glob)
LDAP *ld;
FILE *fp;
char *dn;
int amore;
GLOB_STRUCT *glob;
{
    int        rc, j;
    char        **val, **s;
    char        *rdn;
    LDAPMessage    *res, *e;
    struct timeval    timeout;
    int        classFound;
    pDISPLAY    d_ptr = NULL;
    pDISPLAY_LINE    dis_ptr = NULL;
    SORT_LINE *s_ptr;
    char            la_url[BUFSIZ];
    char      *ufn;
    char already_displayed[BUFSIZ];
    int header_attr_mode = 0;

#if defined( TUE_TEL ) || defined( AMBIXGW )
	char      *parentDN;
#endif


    *already_displayed = ':';
    *(already_displayed+1) = '\0';


    timeout.tv_sec = glob->timeout;
    timeout.tv_usec = 0;


    if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
        NULL, 0, &timeout, &res )) != LDAP_SUCCESS ) {
        do_error(fp, rc, NOT_FOUND, glob);
        return;
    }


    if ( (e = ldap_first_entry( ld, res )) == NULL ) {
        do_error(fp, -2, SERVER_ERROR, glob);
        return;
    }

    val = ldap_get_values( ld, e, "objectClass" );

#if defined( TUE_TEL ) || defined( AMBIXGW )
    /* toc_derefalias: read entry, aliasedObjectName is referring to */
    if(charray_inlist(val, "toc_derefalias")){
        char **new_dn;

        new_dn = ldap_get_values( ld, e, "aliasedObjectName" );
        if(new_dn && new_dn[0]) {
            do_read(ld, fp, new_dn[0], amore, glob);
            return;
        }
    }

    /*  before displaying check for dynamic changes of the sorting parms  */
	parentDN = get_parentDN( dn );
    dynamicResort( ld, glob, parentDN );
#endif

        /* 
         * check for objectClass via displayLists-Table which List
         * of attributes we want to use.
         */
    classFound = -1;
    for(s_ptr = glob->sort; s_ptr; s_ptr = s_ptr->next) {
		char   buf[BUFSIZ];

        d_ptr = s_ptr->display_class_ptr;

        for( j=0; val[j]; j++ ) {
            sprintf( buf, "|%s|", str_tolower( val[j] ));

            if ( strstr( s_ptr->object_class, buf )) {
                 classFound = 1;
                 break;
            }
        }
        if (classFound == 1) break;
    }

#if defined( TUE_TEL ) || defined( AMBIXGW )
    dynamicDisplay( ld, glob, parentDN,
                            s_ptr ? s_ptr->display_class : "default" );
#endif

    if((classFound == -1) && (glob->default_display_type)) {
        d_ptr = glob->default_display_type;
        classFound = 1;
    }

    /* if we did not find a fitting objectClass, simply return */
    if(classFound == -1) {

        fprintf( fp, HTML_HEAD_TITLE, glob->la[22], glob->la[100]);
        fprintf( fp, "\n%s</BODY></HTML>", glob->la[41]);
        return;
    }

    /*  is the display description defined already  */
    if ( !d_ptr && (( d_ptr = find_dPtr( glob->display,
                                s_ptr->display_class )) == NULL )) {

        if ( dosyslog )
            syslog( LOG_INFO,
                    "do_read(%08d): couldn't find display type <%s> -- FATAL.",
                    glob->svc_cnt, s_ptr->display_class );

        fprintf( fp, HTML_HEAD_TITLE, glob->la[22], glob->la[100]);
        fprintf( fp, "\n%s</BODY></HTML>", glob->la[41]);
        return;

    }

    /*  now we can point to the final display screen  */
    dis_ptr = ( amore ? d_ptr->second_page : d_ptr->first_page );

    if (http == 1) PRINT_HTML_HEADER;
    if (request == HEAD) {                
        fflush(fp);
        exit_tweb (1);
    }

    dn = ldap_get_dn( ld, e );

        if ( strcmp( dn, "" ) != 0 ) {  /* Not the root */
        s = ldap_explode_dn( dn, 1 );
                if ( s[1] == NULL )   /* toplevel */
            rdn = ldap_friendly_name( glob->friendlyfile, s[0], &fm );
        else 
            rdn = s[0];
    } else
        rdn = glob->la[77];

    fprintf( fp, HTML_HEAD_TITLE, ufn = friendly_dn( dn, glob ),
                                    glob->la[100] );
    if ( ufn ) free( ufn );

    disp_file(glob, glob->header, fp);

    if ( !glob->ldap_referral_mode ) {

        make_la_buttons("R", fp, ld, dn, la_url, glob);
        make_header( fp, dn, 0, glob );
    } else {
        fprintf( fp, glob->la[105]);
    }
    fprintf( fp, "<DL>");

    fprintf( fp, glob->la[101]);

    /* don't display rdn if first attribute is in header-mode */
    if ( dis_ptr->ty == HEADER )
        header_attr_mode = 1;
    if( ( dis_ptr && !header_attr_mode ) || !dis_ptr ) {
        if(glob->strip_pin && strstr(glob->strip_pin, d_ptr->ocs)) {
            char rdnstriped[BUFSIZ];

            strcpy( rdnstriped, rdn);
            trimright (rdnstriped, " 1234567890");
            fprintf( fp, "<H1>%s</H1>", rdnstriped );
        } else
            fprintf( fp, "<H1>%s</H1>", rdn);
    }

    if(glob->ind_attrs)
        get_ref_attrs( ld, dn, e, glob );

    /* get time for performance log */
    items_displayed = 1;
    gettimeofday(&timestore[4], NULL);

    if ( header_attr_mode )
        rdn = NULL;

    for( ; dis_ptr; dis_ptr = dis_ptr->next) {

        if(glob->ind_attrs){

            int n, m, iatlabel=0, replace=0;
            IND_ATTR_ARR *vnodes;

#ifdef TUE_TEL
            int retcode = 0;

            /* Function Mode */
            retcode = displayTueRefPhone( ld, fp, dn, dis_ptr,
                        e, rdn, glob, already_displayed );
#endif
            if(strstr(already_displayed, dis_ptr->label)) {
                continue;
            }

            vnodes = glob->ind_attrs->valid_nodes;

            for(n=0; vnodes && vnodes[n].key && *(vnodes[n].key) ;  n++) {

                if(!strcasecmp(vnodes[n].attr, dis_ptr->attribute)) {

                    for(m=0; vnodes[n].e[m];  m++)
                        print_attr( vnodes[n].ld, fp, dn,
                               m==0 ? dis_ptr->label : "", dis_ptr->attribute,
                               vnodes[n].e[m], dis_ptr->ty, rdn, glob);

                    iatlabel = 1;
                    if(vnodes[n].replace)
                        replace=1;

                }

            }
            if( iatlabel && !replace)
                print_attr( ld, fp, dn, "",
                   dis_ptr->attribute, e, dis_ptr->ty, rdn, glob);

            if(!iatlabel)
                print_attr( ld, fp, dn, dis_ptr->label,
                   dis_ptr->attribute, e, dis_ptr->ty, rdn, glob);

        } else {
            print_attr( ld, fp, dn, dis_ptr->label,
               dis_ptr->attribute, e, dis_ptr->ty, rdn, glob);
        }
    }


    if ( !amore && d_ptr && d_ptr->second_page ) {

        fprintf( fp, "</DL><A HREF=\"/L%s\"><B>%s</B></A>\n",
                     hex_encode(dn), glob->la[42]);


    }
    fprintf( fp, "</DL>\n");

    if (strcasecmp(dn + strlen(dn) - strlen(glob->basedn->dn),
            glob->basedn->dn) == 0) {

        pMODIF  p_mod;
        char   *aoc;
        char  **oc;

        aoc = make_oc_to_string(oc = ldap_get_values( ld, e, "objectClass" ));

        if(!strlstcmp (aoc, glob->no_modify, '|')) {
          for (p_mod = glob->modify; aoc && p_mod; p_mod = p_mod->next) {
            if (strlstcmp (aoc, p_mod->ocs, '|')) {
                fprintf( fp, "%s<TT>%s</TT><P><FORM ACTION=\"F%s\">\n",
                              glob->la[101], glob->la[43], hex_encode(dn));
                fprintf (fp, "%s <INPUT TYPE=\"password\" ",
                              glob->la[44]);
                fprintf (fp, "NAME=\"userPassword\"><BR>%s  ",
                              glob->la[45]);
                fprintf (fp, "<INPUT TYPE=\"submit\" VALUE=\"%s\">",
                              glob->la[47]);
                fprintf (fp, " %s. </FORM>\n",
                              glob->la[48]);
                break;
            }
          }
        }

        ldap_value_free( oc );

    }

    /* Button leading to cgi-script */
    if( glob->form_button ){
        char  **oc;

        oc = ldap_get_values( ld, e, "objectClass" );
        disp_form_button(1, oc, dn, ld, fp, glob);
    }

    disp_file(glob, glob->footer, fp);

    PRINT_HTML_FOOTER;

}
/* end of function: do_read */

PRIVATE void disp_form_button(read_menu, oc, dn, ld, fp, glob)
int read_menu;
char  **oc;
char *dn;
LDAP *ld;
FILE *fp;
GLOB_STRUCT *glob;
{
    pFORM_BUTTON fo_ptr;
    char dn_used[BUFSIZ], button_label[BUFSIZ];

#ifdef AMBIXGW
    char *who_val;
    char  **selfInsertWho = NULL;
    char  **studie = NULL;
    int selfInsReadFlag = 0;
#endif

    for(fo_ptr = glob->form_button; fo_ptr; fo_ptr = fo_ptr->next) {
        if(read_menu != fo_ptr->read_menu ||
                     ( !charray_inlist(oc, fo_ptr->object_class)
                       && strncasecmp( "cn=", fo_ptr->object_class, 3 ) ) )
            continue;
        strcpy(dn_used, dn);
        strcpy(button_label, fo_ptr->button_label);

#ifdef AMBIXGW
        /* new-AMBIX cn=Selbst-Eintrag etc. support */
        /* object-class field contains here cn=xyz e.g. cn=Selbst-Eintrag */
        if ( !strncasecmp( "cn=", fo_ptr->object_class, 3 )) {
            char dn_buf[BUFSIZ];
            LDAPMessage    *res, *e;
            struct timeval    timeout;
            static char    *attrs[] = { "objectClass", "selfInsertWho",
                                         "studie", 0 };

            /* cn=Selbsteintrag nur einmal lesen */
            if (!selfInsReadFlag ) {
                selfInsReadFlag = 1;

                timeout.tv_sec = glob->timeout;
                timeout.tv_usec = 0;

                sprintf(dn_buf, "%s,%s", fo_ptr->object_class, dn);
                if (ldap_search_st( ld, dn_buf, LDAP_SCOPE_BASE, "objectClass=*",
                    attrs, 0, &timeout, &res ) != LDAP_SUCCESS )
                        continue;
                if(( e = ldap_first_entry( ld, res )) == NULL )
                        continue;

                selfInsertWho = ldap_get_values( ld, e, "selfInsertWho" );
                studie = ldap_get_values( ld, e, "studie" );
            }

            if ( (who_val = strchr(button_label, '|')))
                *who_val++ = '\0';

            if ( !who_val )
                continue;

            if ( !selfInsertWho || !selfInsertWho[0] )
                        continue;

            /* exception for all + studiedn != dn -> two buttons stud + ang */
            if ( strcasecmp(selfInsertWho[0], who_val ) &&
                 !(!strcasecmp(selfInsertWho[0], "all") && studie && studie[0] && dn_cmp(dn, studie[0]) && strcasecmp(who_val, "all")))
                        continue;

            /* filter for exception all-button */
            if( studie && studie[0] && dn_cmp(dn, studie[0]) && !strcasecmp(selfInsertWho[0], "all") && !strcasecmp(who_val, "all") )
                        continue;

            if(!strcasecmp(who_val, "stud" ) && studie && studie[0]
               && dn_cmp(dn, studie[0]))
                strcpy(dn_used, studie[0]);
        }
#endif

        fprintf (fp, "<FORM METHOD=%s ACTION=%s>\n", fo_ptr->method,
                      fo_ptr->script_url);
        fprintf (fp, "%s\n<INPUT type=hidden name=\"%s\" value=\"%s\">\n",
                      fo_ptr->text, fo_ptr->dn_name, hex_encode(dn_used));
        fprintf (fp, "<INPUT TYPE=\"submit\" name=\"%s\" value=\"%s\">\n",
                      fo_ptr->form_name, button_label);
        fprintf (fp, "</FORM>\n");
    }
}
/* end of function: disp_form_button */


PUBLIC void do_form(ld, fp, query, glob)
LDAP *ld;
FILE *fp;
char *query;
GLOB_STRUCT *glob;
{
        int             rc, count;
        char            *dn = query, *pw;
        char            *ufn;
        char            *a;
        LDAPMessage     *res, *e;
        struct timeval  timeout;
        pMODIFY_LINE mod_ptr;
        char title[BUFSIZ];


        if ( (pw = strchr( dn, '?' )) == NULL ) {
                fprintf( fp, "%s<br>", glob->la[49]);
                exit_tweb( 1 );
        }
        *pw++ = '\0';
        if (strncmp(pw, "userPassword=", 13) == 0)
                pw += 13;
        else {
                fprintf( fp, "%s %s!<br>", glob->la[50], pw);
                exit_tweb ( 1 );
        }
    if (strlen(pw) == 0) {
        /* we need a password for simple auth */
        do_error( fp, LDAP_INVALID_CREDENTIALS, FORBIDDEN, glob);
        rewind(fp);
        exit_tweb( 1 );
    }
        if ( (rc = ldap_simple_bind_s( ld, dn, pw )) != LDAP_SUCCESS ) {
                if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
                do_error( fp, rc, FORBIDDEN, glob);
                return;
        }
        if (debug) fprintf(stderr, "BOUND as %s\n", dn);
        timeout.tv_sec = glob->timeout;
        timeout.tv_usec = 0;
        if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
            0, 0, &timeout, &res )) != LDAP_SUCCESS ) {
                do_error(fp, rc, NOT_FOUND, glob);
                return;
        }
        if ( (e = ldap_first_entry( ld, res )) == NULL ) {
                do_error(fp, -2, SERVER_ERROR, glob);
                return;
        }
        dn = ldap_get_dn( ld, e );
        ufn = ldap_dn2ufn( dn );
        if (http == 1) {
        PRINT_HTML_HEADER;
        }
    sprintf( title, "%s %s", glob->la[51], ufn );
    fprintf( fp, HTML_HEAD_TITLE, title, glob->la[100] );

    disp_file(glob, glob->header, fp);

        fprintf( fp, "<FORM ACTION=\"Y%s\">\n<INPUT TYPE= \"radio\" ", hex_encode(dn));
        fprintf( fp, "NAME=\"oldPassword\" VALUE=\"%s\" CHECKED><TT>%s</TT>\n<H1>%s</H1><DL><br>", hex_encode(pw), glob->la[53], ufn );
        free( ufn );
    for(mod_ptr = glob->modify->modattr; mod_ptr; mod_ptr = mod_ptr->next){
        a = mod_ptr->attribute;
        count = mod_ptr->count;
                if ( strcmp( a, "homepostaladdress" ) == 0
                    || strcmp( a, "postaladdress" ) == 0) 
            if (count == 0)
                            print_attr(ld,fp,dn,mod_ptr->label,a,e,MULTILINE,NULL, glob);
            else
                            form_attr(ld,fp,mod_ptr->label,a,e,1,count, glob);
                else if (count == 0)
                    print_attr( ld, fp, dn, mod_ptr->label, a, e, DEFAULT, NULL, glob);
        else
                    form_attr( ld, fp, mod_ptr->label, a, e, 0, count, glob );
    }
        fprintf( fp, "</DL><InPut TYPE=\"reset\" VALUE=\"%s\"> ", glob->la[72]);
        fprintf( fp, "<InPut TYPE=\"submit\" VALUE=\"%s\">", glob->la[47]);
        fprintf( fp, "</FORM>");

    disp_file(glob, glob->footer, fp);

        PRINT_HTML_FOOTER;
    fflush(fp);
}
/* end of function: do_form */


PUBLIC void do_modify(ld, fp, query, glob)
LDAP    *ld;
FILE *fp;
char *query;
GLOB_STRUCT *glob;
{
    char *dn, *ufn, *pw, *what, *next, *val, *oldval, *cp;
    int     rc, changes = 0, delete_flag;
    static char    *value1[2], *value2[2];
    static LDAPMod mod1, mod2;
    static LDAPMod *mods[3] = { &mod1 , &mod2, NULL};
    char title[BUFSIZ];

/*  Patch: we can't run the modification of attributes in two distinct steps,
       since inheritage might copy a value into the entry after deletion
       of the old value

    /KSp, 95/07/13
*/


    /* query: DN?oldPassword=oldpw&att1=oldval1=val1&att2=oldval2=val2&...
     * or:    DN?oldPassword=oldpw&att1%3Doldval1=val1&att2%3Doldval2=... 
     */

    dn = query;
    rewind(fp);

        if ( (what = strchr( dn, '?' )) == NULL ) {
                explain_error( fp, glob->la[93], BAD_REQUEST, glob );
                exit_tweb( 1 );
        }
        *what++ = '\0';
        hex_decode(dn);
        if (debug) fprintf(stderr, "What: %s\n", what);    
    /* At first there should be the old userPassword */
    if ( (pw = strstr( what, "oldPassword")) == NULL ) {
        explain_error( fp, glob->la[94], BAD_REQUEST, glob);
        exit_tweb ( 1 );
    }
        pw += 12;        /* strlen("oldPassword") + 1 */
    /* skip to the first real attribute */
    if ( (what = strchr(pw, '&'))  == NULL ) {
        explain_error( fp, glob->la[95], BAD_REQUEST, glob);
        exit_tweb( 1 );
    }
    *what++ = '\0';
    hex_qdecode(pw);
    if (debug) fprintf(stderr, 
         "\ndo_modify: DN = %s PW = #######  CONTENT =\n%s\n ", dn, what );
    if ( (rc = ldap_simple_bind_s( ld, dn, pw )) != LDAP_SUCCESS ) {
            if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
            do_error( fp, rc, FORBIDDEN, glob);
            exit_tweb( 1 );
    }
    if (debug) fprintf(stderr, "BOUND as %s.\n", dn);

    if (http == 1) {
        PRINT_HTML_HEADER;
    }

    if (request == HEAD) {
        fflush(fp);
        exit_tweb (1);
    }
    ufn = ldap_dn2ufn( dn );
    sprintf( title, "%s %s", glob->la[8], ufn);
    fprintf(fp, HTML_HEAD_TITLE, title, glob->la[100]);

    disp_file(glob, glob->header, fp);

    fprintf(fp, "<H2>%s %s</H2>%s<DL>\n", glob->la[9],  ufn, glob->la[10]);
    free(ufn);

        while (what) {
                if ((next = strchr(what, '&')) != NULL) {
            *next++ = '\0';
        } else {    /* last in query */
            next = NULL;
        }
        if ((val = strrchr(what, '=')) == NULL) {
            /* new value */
            fprintf( fp, "<P>%s ", glob->la[54]);
                        fprintf( fp, "%s %s!<P>", glob->la[55], hex_qdecode(what));
            exit_tweb (1);
        }
        *val++ = '\0';
        hex_qdecode(what);
        hex_qdecode(val);
        if ((oldval = strchr(what, '=')) == NULL) {
            /* old value */
            fprintf( fp, "<P>%s ", glob->la[56]);
            fprintf( fp, "%s %s!<P>\n", glob->la[55], what);
            exit_tweb (1);
        }
        *oldval++ = '\0';
        if (strcmp(oldval, val) == 0 ) {    /* no changes */
            what = next;
            continue;
        }
        if ((strcasecmp(what, "homePostalAddress") == 0) ||
            (strcasecmp(what, "postalAddress") == 0)) {
            /* multiline */
            cp = oldval;
            while ((cp = strchr(cp, '\n')) != NULL) *cp = '$';
            cp = val;
            while ((cp = strchr(cp, '\n')) != NULL) *cp = '$';
                }
        if (debug)
            fprintf(stderr, 
                             "what = %s, oldval = %s, val = %s\n", 
                             what, oldval, val);

        /* there is something to do:
         * - delete the old value
         * - add the new value if not empty */
        mod1.mod_type = what;
        mod2.mod_type = what;
        value1[1] = NULL;
        value2[1] = NULL;
        mod1.mod_values = value1;
        mod2.mod_values = value2;
        mods[1] = NULL;
        delete_flag = FALSE;

/*  #############  */

        if (strlen(oldval) > 0) {

            if (strlen (val) > 0) {

                mod1.mod_op = LDAP_MOD_ADD;
                value1[0] = val;

/*                mod2.mod_op = LDAP_MOD_DELETE;
                value2[0] = oldval;
                mods[1] = &mod2;
*/
                if ((rc = ldap_modify_s(ld, dn, mods)) != LDAP_SUCCESS) {

                    fprintf( fp, 
                    "%s <TT>%s</TT> %s <TT>%s</TT>!<P>\n<EM> %d: %s.</EM><p>\n",
                            glob->la[80], oldval, glob->la[81], what, 
                            rc, ldap_err2string(rc));

                    what = next;
                    continue;

                }

                mod1.mod_op = LDAP_MOD_DELETE;
                value1[0] = oldval;

            } else {

                mod1.mod_op = LDAP_MOD_DELETE;
                value1[0] = oldval;
                delete_flag = TRUE;

            }

        } else  {
        
            mod1.mod_op = LDAP_MOD_ADD;
            value1[0] = val;

        }

        if (debug) 
              fprintf(stderr, "trying: %s = %s.\n", what, val);

        if (((rc=ldap_modify_s(ld, dn, mods)) != LDAP_SUCCESS) &&
            (mod1.mod_op != LDAP_MOD_DELETE) && (rc != LDAP_NO_SUCH_ATTRIBUTE)){

if (dosyslog)
    syslog (LOG_INFO, "ERROR: ldap_modify_s: ADD\n");
            if ( debug ) 
                ldap_perror( ld, "ldap_modify_s: ADD");
            fprintf( fp, 
                "%s <TT>%s</TT> %s <TT>%s</TT><P>\n%s <EM> %d: %s.</EM><P>\n", 
                glob->la[57], val, glob->la[58], what, glob->la[59], 
                rc, ldap_err2string( rc ) );
            if (strlen(oldval) > 0 && rc != LDAP_INSUFFICIENT_ACCESS) {
                /* try to reset to old value */

                mod1.mod_op = LDAP_MOD_ADD;
                mods[1] = NULL;

                value1[0] = oldval;
                if ((rc = ldap_modify_s(ld, dn, mods)) != LDAP_SUCCESS) {
                    fprintf( fp, 
                    "%s <TT>%s</TT> %s <TT>%s</TT>!<P>\n<EM> %d: %s.</EM><P>\n",
                                glob->la[60], oldval, glob->la[61], what, 
                                rc, ldap_err2string(rc));

                    exit_tweb( 1 );
                } else {
                    fprintf( fp, "%s <TT>%s</TT> %s <TT>%s</TT><P>\n", 
                                glob->la[62], oldval, glob->la[61], what);
                }
            }
            what = next;
            continue;
        }

        if (debug) fprintf(stderr, "MOD: %s = %s.\n", what, val);
        changes++;
        fprintf(fp, "<DT><B>%s</B> <DD>%s <TT>(%s)</TT>\n",
            ldap_friendly_name(glob->friendlyfile, what, &fm), value1[0],
            delete_flag ? glob->la[74] : strlen(oldval) > 0 ? 
                                        glob->la[75] : glob->la[76]);
        what = next;
        }
    fprintf(fp, "</DL>%d %s%s%s!\n", changes, glob->la[15], 
                    changes != 1 ? glob->la[73] : "", 
                    changes > 0 ? glob->la[16] : "");
    if (changes > 0) {
        char  *dn2 = hex_encode(dn);

        fprintf(fp, "<UL><LI><B><A HREF=\"/R%s\">%s</A>\n",
            dn2, glob->la[17]);
        fprintf(fp, "<LI><A HREF=\"/F%s?userPassword=%s\">%s</A></B></UL>\n", 
            dn2, pw, glob->la[19]);

    }

    disp_file(glob, glob->footer, fp);

    PRINT_HTML_FOOTER;
    fflush(fp);
}
/* end of function: do_modify */

PRIVATE int no_show( rdn, glob)
char *rdn;
GLOB_STRUCT *glob;
{
    if ( glob->no_show_rdn ) {

        char rdn_cpy[BUFSIZ], *toc, no_sh[BUFSIZ];

        strcpy(no_sh, glob->no_show_rdn);
        sprintf(rdn_cpy, "|%s|", rdn);
        toc = strtok(no_sh, " ");
        do {
            if(strstr(str_tolower((char *) rdn_cpy), str_tolower(toc)))
                return(TRUE);
        } while( ( toc = strtok(NULL, " ")) );

    }

    return(FALSE);
}
/* end of function: no_show */


PRIVATE int sort_result(ld, res, dn, glob)
LDAP *ld;
LDAPMessage *res;
char *dn;
GLOB_STRUCT *glob;
{
    LDAPMessage    *e;
    char    *ufn;
    int counter = 0, baselen;
    int basecount;
    pSORT_LINE  s_ptr;
    pMY_LDAP_LIST lmptr;
    LFP getfirst = glob->prefer_ref_uris ? my_first_entry : ldap_first_entry,
        getnext  = glob->prefer_ref_uris ? my_next_entry : ldap_next_entry;

    hex_decode (dn);

    ufn = ldap_dn2ufn(dn);
    baselen = ufn ? strlen(ufn) : 0;
    basecount = ufn ? chrcnt(ufn, UFNSEP) : 0;

#if defined( TUE_TEL ) || defined( AMBIXGW )
    /*  before sorting check for dynamic changes of the sorting instructions  */
    dynamicResort( ld, glob, dn );
#endif

    for ( e = (*getfirst)(ld, res);     e != NULL && counter < glob->maxcount;
          e = (*getnext)(ld, e ) ) {
       sort_parse(ld, e, dn, ufn, baselen, basecount, counter, glob);
    }
    for(lmptr = mllroot; lmptr; lmptr = lmptr->next) {
        sort_parse(ld, lmptr->e, dn, ufn, baselen, basecount, counter, glob);
    }
    mllroot = NULL;

    for(s_ptr = glob->sort; s_ptr; s_ptr = s_ptr->next) {
        if( s_ptr->dnLast )
            qsort(s_ptr->dnList, s_ptr->dnLast, sizeof(int), compare);
    }
    return counter;
}
/* end of function: sort_result */


PRIVATE void list_output(fp, glob)
FILE *fp;
GLOB_STRUCT *glob;
{
    int i, x;
    pSORT_LINE s_ptr;

    if(glob->tables_marker)
        fprintf (fp, "</H3><TABLE WIDTH=\"100%%\">");

    for (i = 0 ; i < MAX_OCS ; i++ ) {
        if(!glob->sorty[i]) continue;
        s_ptr = glob->sorty[i];

        if(glob->tables_marker)
            fprintf( fp, "<TR><TH ALIGN=LEFT><BR>");

        fprintf( fp, "<H3>%s", s_ptr->label);

#ifdef TUE_TEL
        if(glob->ton_urls && glob->ton_urls->department
                          && (strlen(s_ptr->label) >1) ) 
            fprintf( fp, " / %s", glob->ton_urls->department);
#endif

        if(s_ptr->restricted) {
            fprintf( fp, " %s", glob->la[33]);
            if (glob->legal && !glob->legal_top)
                fprintf( fp, ", %s", glob->la[34]);
            fprintf (fp, ")");
        }

        if(glob->tables_marker)
            fprintf (fp, "</H3></TH></TR>");
        else
            fprintf (fp, "</H3><MENU>\n");

        for(x=0; x < s_ptr->dnLast; x++) {
            if(glob->strip_pin && strstr(glob->strip_pin, s_ptr->object_class)){
                s_ptr->dnList[x]->href[strlen(s_ptr->dnList[x]->href) -5] = '\0';
                trimright (s_ptr->dnList[x]->href, " 1234567890");
                strcat(s_ptr->dnList[x]->href, "</A>\n");
            }
    
            if( glob->raw_data ) {
                fprintf(fp,"%s",s_ptr->dnList[x]->raw);
                free(s_ptr->dnList[x]->raw);
            } else {
                fprintf(fp,"%s",s_ptr->dnList[x]->href);
                free(s_ptr->dnList[x]->href);
            }
            free(s_ptr->dnList[x]->string);
        }

        if(!glob->tables_marker)
            fprintf (fp, "</MENU>\n");

        glob->sorty[i] = NULL;
    }
    if(glob->tables_marker)
        fprintf (fp, "</TABLE>\n");
}
/* end of function: list_output */

PRIVATE void make_la_buttons(sep, fp, ld, dn, la_url, glob)
char *sep;
FILE *fp;
LDAP *ld;
char *dn;
char *la_url;
GLOB_STRUCT *glob;

{
    int k;

    /* Inform users from unknown */
    if(glob->unknown_host) fprintf( fp, glob->la[102]);

    if(glob->legal && glob->legal_top)
        fprintf (fp, "%s\n%s\n",
                glob->is_proxy ? glob->la[104] : glob->la[65], glob->la[101]);

    /* if allowed -> allow-file-message */
    if(glob->allowed && glob->allow_msg)
        disp_file(glob, glob->allow_msg, fp);

    if(glob->pull_down_menus) {
        make_la_buttons_pull_down(sep, fp, ld, dn, la_url, glob);
        return;
    }

    fprintf( fp, "<B>");
    fprintf( fp, " [ <A HREF=\"/H\">%s</A> ] ",glob->la[29]);
    for(k=0; k<strlen(glob->olang); k++){
        if(glob->olang[k] == glob->lang[0]) continue;
        sprintf(la_url, "http://%s:%d/%s%s",
                    glob->hostname, glob->webport+glob->olang[k]-'0',
                    sep, hex_encode(dn));
        fprintf( fp, " [ <A HREF=\"%s\"> %s </A> ] ",
                    la_url, glob->language[glob->olang[k]-'0']);
    }
    fprintf( fp, "</B><p>");
}
/* end of function: make_la_buttons */

PRIVATE void make_la_buttons_pull_down(sep, fp, ld, dn, la_url, glob)
char *sep;
FILE *fp;
LDAP *ld;
char *dn;
char *la_url;
GLOB_STRUCT *glob;

{
    int k;
    TABLE_DISPLAY *tab_ptr;

    fprintf( fp, "<FORM ACTION=\"/B\">\n");
    fprintf( fp, "<INPUT TYPE=SUBMIT NAME=H Value = \"%s\">\n",glob->la[29]);

    fprintf( fp, "_\n");

    for(k=0; k<strlen(glob->olang); k++){
        if(glob->olang[k] == glob->lang[0]) continue;
        sprintf(la_url, "http://%s:%d/%s%s",
                    glob->hostname, glob->webport+glob->olang[k]-'0',
                    sep, hex_encode(dn));
        fprintf( fp, "<INPUT TYPE=SUBMIT NAME=%s Value = \"%s\">\n", 
                      la_url, glob->language[glob->olang[k]-'0']);
    }

    /* make tables button in order to have table-display requests */
    for(tab_ptr = glob->tables; tab_ptr; tab_ptr = tab_ptr->next) {

        char **oc = NULL;
        struct timeval timeout;
        LDAPMessage *res;
        static char    *attrs[] = { "objectClass", 0 };

        if( !((!tab_ptr->allow || glob->allowed) && !glob->tables_marker))
            continue;

        /* Check objectclass for tables_oc */
        timeout.tv_sec = glob->timeout;
        timeout.tv_usec = 0;
        if ( ldap_search_st( ld, dn, LDAP_SCOPE_BASE, "objectClass=*",
                              attrs, 0, &timeout, &res ) == LDAP_SUCCESS ){
            oc = ldap_get_values(ld, ldap_first_entry(ld, res), "objectClass");
        }
        if ( oc && charray_inlist( oc, tab_ptr->select_oc)) {

            fprintf( fp, "_______\n");
            fprintf( fp, "<INPUT TYPE=SUBMIT NAME=X%s?%s#%s Value = \"%s\">\n",
                       hex_encode(dn),
#ifdef TUE_TEL
                       strstr(tab_ptr->dn_extension, "persontable") ?
                       "MENU" : "PHONEBOOK",
#else
                       "MENU",
#endif
                       tab_ptr->dn_extension, tab_ptr->button_label);
        }
    }

    fprintf( fp, "</FORM>\n");
}
/* end of function: make_la_buttons_pull_down */

PRIVATE void print_rdn(fp, dn, glob)
FILE *fp;
char *dn;
GLOB_STRUCT *glob;
{
    char        **s;
    char        *rdn = NULL;

    if(glob->pull_down_menus) {
        print_rdn_pull_down(fp, dn, glob);
        return;
    }

    s = ldap_explode_dn( dn, 1 );
    if ( strcmp( dn, "" ) != 0 ) {    /* Not the root */
        if ( s[1] == NULL ) {    /* toplevel */
            rdn = ldap_friendly_name( glob->friendlyfile, s[0], &fm );
        } else {
            rdn = s[0];
        }
        fprintf( fp,"%s <B><A HREF=\"/R%s\">%s</A></B>\n",glob->la[28],hex_encode(dn),rdn?rdn:s[0]);
    } else {            /* the root */
        fprintf( fp, "<B>%s</B>\n", glob->la[77]);
    }
    ldap_value_free( s );
}
/* end of function: print_rdn */

PRIVATE void print_rdn_pull_down(fp, dn, glob)
FILE *fp;
char *dn;
GLOB_STRUCT *glob;
{
    char        **s;
    char        *rdn = NULL;

    fprintf( fp, "<FORM ACTION=\"/B\">\n");

    s = ldap_explode_dn( dn, 1 );
    if ( strcmp( dn, "" ) != 0 ) {    /* Not the root */
        if ( s[1] == NULL ) {    /* toplevel */
            rdn = ldap_friendly_name( glob->friendlyfile, s[0], &fm );
        } else {
            rdn = s[0];
        }
        fprintf( fp,"%s <BIG><STRONG>%s</STRONG></BIG>  ",
                     glob->la[28], rdn?rdn:s[0]);
        fprintf( fp, "<INPUT TYPE=SUBMIT NAME=R%s Value = \"%s\">\n",
                       hex_encode(dn), glob->la[98]);
    } else {            /* the root */
        fprintf( fp, "<BIG><STRONG>%s</STRONG></BIG>\n", glob->la[77]);
    }
    ldap_value_free( s );
    fprintf( fp, "</FORM>\n");
}
/* end of function: print_rdn_pull_down */

PRIVATE void make_search_box(fp, ld, dn, glob)
FILE *fp;
LDAP *ld;
char *dn;
GLOB_STRUCT *glob;
{
    int scope;

    scope = make_scope(ld, dn, glob);    /* onelevel or subtree search ? */
    fprintf( fp, "<DL><DT><FORM ACTION=\"/S%s\">%s  <inPUT NAME=\"%s\"><INPUT TYPE=submit VALUE=%s><INPUT TYPE=reset VALUE=\"%s\">\n",
        hex_encode(dn),
        scope == LDAP_SCOPE_ONELEVEL ? glob->la[66] : glob->la[67],
        scope == LDAP_SCOPE_ONELEVEL ? "O" : "S",
        glob->la[68], glob->la[69]);

    fprintf( fp, "</FORM></DL>\n");
}
/* end of function: make_search_box */

PRIVATE LDAPMessage *my_first_entry( ld, e )
LDAP *ld;
LDAPMessage *e;
{
    return(ldap_list_eval(ld, e , ldap_first_entry));
}
/* end of function: my_first_entry */

PRIVATE LDAPMessage *my_next_entry(ld, e )
LDAP *ld;
LDAPMessage    *e;
{
    return(ldap_list_eval(ld, e , ldap_next_entry));
}
/* end of function: my_next_entry */

PRIVATE LDAPMessage *ldap_list_eval(ld, e, funcp )
LDAP *ld;
LDAPMessage    *e;
LFP funcp;
{

    char **value = NULL;
    pMY_LDAP_LIST *lmhandle; /* , lmptr; */

    for(lmhandle = &mllroot; *lmhandle; lmhandle = &(*lmhandle)->next)
        ;

    for( e =  (*funcp)( ld, e ) ;
         e && strstr(make_oc_to_string(value = ldap_get_values( ld, e, "objectClass" )),
                 "|alias|");     e = ldap_next_entry( ld, e )) {
        *lmhandle = (pMY_LDAP_LIST) ch_malloc(sizeof(MY_LDAP_LIST));
        (*lmhandle)->e = e;
        lmhandle = &(*lmhandle)->next;
        ldap_value_free(value);
        value = NULL;

    }
    if (value) ldap_value_free(value);

/*    if(!e) {
        for(lmptr = mllroot; lmptr; lmptr = lmptr->next) {
            char **val;

            val = ldap_get_values(ld, lmptr->e, "aliasedObjectName");
if (dosyslog) syslog (LOG_INFO, "alias: %s", val[0]);
            ldap_value_free(val);
        }
        mllroot = NULL;
    }
*/
    return(e);
}
/* end of function: ldap_list_eval */

PRIVATE void sort_parse(ld, e, dn, ufn, baselen, basecount, counter, glob)
LDAP *ld;
LDAPMessage *e;
char *dn;
char *ufn;
int baselen;
int basecount;
int counter;
GLOB_STRUCT *glob;
{
    char    **s, **oc;
    char    *dn2, *urldn = NULL, *rdn, *doc, *aoc;
    char    *ufn2, *sortstring = NULL, *cp;
    char   **sattr = NULL, href[20*BUFSIZ], *temp;
    int spaces = 0, iscountry;
    pGW_SWITCH_LINE gw_ptr;
    int flag, found_oc, i;
    pSORT_LINE *s_hndl;
    pSORT_LINE  s_ptr;
    char *url = NULL;
    char **uri = NULL, *urlnola, raw_string[BUFSIZ];

#if OL_LDAPV > 0
	int         ldap_opt;
#endif

    oc = ldap_get_values( ld, e, "objectClass" );

    if(!(aoc = make_oc_to_string(oc))) return;


#ifdef TUE_TEL
    /*** ton_urls ***/
    if(glob->ton_urls && glob->ton_urls->value && strstr(aoc, "|person|")) {
        char **tonvals;
        int k, matched;

        matched=0;
        tonvals = ldap_get_values( ld, e, glob->ton_urls->attribute);
        if(!tonvals) return;
        for(k=0; tonvals[k]; k++) {
            if(strstr(tonvals[k], glob->ton_urls->value)
            && !(strchr(tonvals[k], '.')
                 && (strcspn(tonvals[k],".") > strlen(glob->ton_urls->value)))){
                matched = 1;
            }
        }
        if(!matched) {
            return;
        }
    }
#endif

    /* Begin New Sort */
    found_oc = FALSE;
    i        = 0;
    for(s_hndl = &(glob->sort); *s_hndl; s_hndl = &(*s_hndl)->next) {

        i++;
        if(strstr( aoc, (*s_hndl)->object_class )) {

            if(strstr(aoc, "|person|") && glob->no_browse)
                goto NEXTENTRY;
            found_oc = TRUE;
        }
        if(found_oc) break;
    }

    if(!found_oc) {
        if(glob->show_defoc) {
            *s_hndl = s_ptr = (pSORT_LINE) ch_malloc(sizeof(SORT_LINE));
            s_ptr->object_class = strdup(pick_oc(oc));
            s_ptr->label = ldap_friendly_name(glob->friendlyfile, 
                                s_ptr->object_class, &fm);
            s_ptr->priority = i;

        } else return;
    }

    s_ptr = *s_hndl;
    doc   = s_ptr->object_class;

    dn2 = ldap_get_dn( ld, e );
    if(urldn) free(urldn);
    if(strstr(aoc, "|alias|")) {

        char **val;

        val = ldap_get_values(ld, e, "aliasedObjectName");
        urldn = strdup(hex_encode(val[0]));
        ldap_value_free(val);

    } else
        urldn = strdup(hex_encode(dn2));

    ufn2 = strdup (ldap_dn2ufn(dn2));
    s = ldap_explode_dn( dn2, 1 );

    if(baselen)
        ufn2 = dnrcut(ufn2, UFNSEP, basecount);

    /* Support raw data delivery */
    if(glob->raw_data) {
        char **rvals;
        int k, l;

        sprintf(raw_string, "%s", ufn2);
        trimright (raw_string, " 1234567890");

        for(l=0; glob->raw_attrs[l]; l++) {
            rvals = ldap_get_values( ld, e, glob->raw_attrs[l]);
            if(rvals[0])
                sprintf(raw_string, "%s%% %s=", raw_string, glob->raw_attrs[l]);
            for(k=0; rvals[k]; k++) {
                sprintf(raw_string, "%s%s%s",raw_string, 
                                             k>0 ? "&":"", rvals[k] );
            }
        }
        sprintf(raw_string, "%s|<br><br>", raw_string);
    }

    iscountry = (strstr( doc, "country" ) != NULL);
    if ( iscountry ) {
        rdn = ldap_friendly_name( glob->friendlyfile, s[0], &fm );
        sortstring = ufn2 = ldap_friendly_name( glob->friendlyfile, 
                                                                ufn2, &fm );
        sattr = NULL;
    } else
        rdn = s[0];
    if ( rdn == NULL )
        rdn = s[0];
    if (( strncasecmp( rdn, "{ASN}", 5 ) == 0 ) 
                 || no_show( rdn, glob)) {
        free( dn2 );
        ldap_value_free( s );
        ldap_value_free( oc );
            return;
    }
    if ( !iscountry ) {    /* not a country */
        sattr = ldap_get_values( ld, e, s_ptr->sort_attr);
        sortstring = strdup(dn2);
        if ( ( cp = strchr(sortstring,'=')) ) {
            sortstring = ++cp;
            /* DNs may have components in '"', ignored  when sorting */
            if ( *sortstring == '"' )
            sortstring++;
        }
        if ( sattr ) {
            cp = *sattr;
            while ( ( cp = strchr(cp,' ')) ) {
                cp ++;
                spaces ++;
            }
        }
        while ( spaces > 0 ) {
            if ( ( cp = strrchr(sortstring,' ')) ) {
                *cp = '\0';
                spaces --;
            }
        }
    }

    ufn2 = trim(ufn2, "\"");

    /* GW-SWITCH */
    flag = 0;
    urlnola = NULL;

    if (glob->gw_switch && glob->gw_switch->dynamic) {

        uri = ldap_get_values( ld, e, "labeledURI" );

        /* PREFER-REF-URIS Code */
        if(strstr(aoc, "|alias|") && glob->prefer_ref_uris){

            LDAPMessage *ures, *ue;
            struct timeval  timeout;
            char        **val;

            timeout.tv_sec = glob->timeout;
            timeout.tv_usec = 0;
    
#if OL_LDAPV > 0

		ldap_opt = LDAP_DEREF_ALWAYS;
        ldap_set_option( ld, LDAP_OPT_DEREF, &ldap_opt );

#else
            ld->ld_deref = LDAP_DEREF_ALWAYS;
#endif

            if ( (ldap_search_st( ld, dn2, LDAP_SCOPE_BASE, "objectClass=*",
                NULL, 0, &timeout, &ures )) == LDAP_SUCCESS ) {
                if ( (ue = ldap_first_entry( ld, ures ))) {
                    if( ( val = ldap_get_values( ld, ue, "labeledURI" )) ) {
                        if(uri) ldap_value_free(uri);
                        uri = val;
                            
                    }
                }
            }
        }

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
            if (!dn_cmp (dn2, gw_ptr->dn)) {
                flag = 1;
                url = gw_ptr->url;
            }
        }
    }

        if(flag == 1) {
            char  *url_tmp;

            sprintf( href, "<LI><A HREF=\"%s\">%s</A>\n",
                        (url_tmp = url_complete(url, urldn, "M")),
                         glob->disp_sea_rdn ? rdn : ufn2);

        }

        if (flag==0) {
            char *strptr;

            if(glob->strip_pin && strstr(glob->strip_pin, doc))
                if ( ( strptr = strchr(ufn2, ',')) ) {

                    *strptr++ = '\0';
                    trimright(ufn2, " 1234567890");
                    sprintf(ufn2, "%s,%s", ufn2, strptr);

                } else
                    trimright(ufn2, " 1234567890");

            ufn2 = trim(ufn2, "\"");

            /* TABLES DISPLAY CODE */
            if(glob->tables_marker){

                char disp_rule[BUFSIZ], *strptr, strbuf[BUFSIZ];
                char tab_attr[BUFSIZ], percent[BUFSIZ];
                char **aval;
                int n;

                strcpy(disp_rule, glob->tables_marker);
                strptr = strstr(disp_rule, "persontable");

                if(strptr){
                    strptr = strchr(strptr, ':') + 1;
                    strcpy(disp_rule, strptr);
                    strptr = strchr(disp_rule, '$');
                    if(strptr) *strptr = '\0';
                    strcat(disp_rule, "&");

                    strcpy( href, "<TR>\n");

                    while(*disp_rule){
                        strcpy(strbuf, disp_rule);
                        strptr=strchr(disp_rule, '&');
                        strcpy(disp_rule, strptr+1);

                        strptr=strchr(strbuf, '&');
                        *strptr++ = '\0';
                        strcpy(tab_attr, strbuf);
                        strptr = strchr(tab_attr, ',');
                        *strptr++ = '\0';
                        strcpy(percent, strptr);

                        sprintf( href, "%s <TD WIDTH=\"%s%%\" VALIGN=TOP %s>",
                                 href, percent,
                                 !strcasecmp(tab_attr, "telephonenumber") ?
                                 "ALIGN=RIGHT NOWRAP" : "ALIGN=LEFT");

                        if(!strcasecmp(tab_attr, "rdn")){
                            trimright (ufn2, " 1234567890");
                            sprintf( href, "%s<A HREF=\"/M%s\">%s</A><BR>\n",
                                     href, urldn, ufn2);

#ifdef TUE_TEL
                        /* use tat_refphone & fallback to telephonenumber */
                        } else if(!strcasecmp(tab_attr, "phone")){
                            displayTueTelList( ld, e, href, glob );

#endif
                        } else if(!strncasecmp(tab_attr, "objectclass", 11)){
                            char objectclass[BUFSIZ], letter[BUFSIZ], *trptr;
                            char tab_attr_buf[BUFSIZ];

                            *(letter+1) = *letter = '\0';
                            strcpy(tab_attr_buf, tab_attr);
                            trptr = tab_attr_buf;
                            while( ( trptr = strchr(trptr, '=')) )
                                *trptr++ = ' ';

                            sscanf(tab_attr_buf, "%*s%s%s",
                                              objectclass, letter);
                            if(!*letter) *letter = '*';

                            if( ( aval =
                                    ldap_get_values( ld, e, "objectclass")) ) {
                                if(charray_inlist(aval, objectclass))
                                    sprintf(href, "%s %s",
                                                      href, letter);
                            }
                        } else if( ( aval =
                                        ldap_get_values( ld, e, tab_attr )) ) {
                            for(n=0; aval[n]; n++){
                                if(!strcasecmp(tab_attr, "mail"))
                                    sprintf(href,
                                            "%s<A HREF=\"mailto:%s\">%s</A><BR>",
                                            href, aval[n], aval[n]);
                                else
                                    sprintf(href, "%s %s<BR>", href, aval[n]);
                            }
                        }
                        sprintf( href, "%s</TD>", href);
                    }
                    sprintf( href, "%s</TR>", href);
                }

            /* without tables */
            }else{
                sprintf( href, "<LI><A HREF=\"%s%sM%s\">%s</A>\n",

#ifdef TUE_TEL
                         (glob->dit_config && !glob->dit_config->not_browse) ?
                                dn2server(urldn, glob) : "",
#else
                                "",
#endif

                                "/", urldn,
                                glob->disp_sea_rdn ? rdn : ufn2);
            }
        }

        if (*sortstring == '&') {

            sortstring[0] = sortstring[1];
            sortstring[1] = 'e';

        }

        if( (strstr(aoc, "person") && (s_ptr->dnLast >= glob->max_person) )
           || ( s_ptr->dnLast >= glob->maxcount) ) {
            s_ptr->restricted = 1;
            return;
        }

        if ( sattr ) 
            temp = (char *) ch_malloc(strlen(*sattr)+strlen(sortstring)+1);
        else 
            temp = (char *) ch_malloc(strlen(sortstring)+1);
        if ( sattr )
            strcat(temp, *sattr);
        strcat(temp,sortstring);

        if(!s_ptr->dnList)
            s_ptr->dnList = (DNLIST **) ch_calloc(glob->maxcount+1,
                                                     sizeof(pDNLIST));
        if (!s_ptr->dnList[s_ptr->dnLast] )
                    s_ptr->dnList[s_ptr->dnLast] = (pDNLIST)
                                        ch_malloc(sizeof(DNLIST));

        s_ptr->dnList[s_ptr->dnLast]->string = temp;

        if(glob->raw_data) {
            s_ptr->dnList[s_ptr->dnLast]->raw = strdup(raw_string);
        }

        s_ptr->dnList[s_ptr->dnLast++]->href = strdup(href);
        glob->sorty[s_ptr->priority] = s_ptr;

        free( dn2 );
        ldap_value_free( s );
        ldap_value_free( oc );
        ldap_value_free( uri );

        if(++counter >= glob->maxcount)
            glob->restricted = TRUE;

NEXTENTRY:
        ;
        return;
}
/* end of function: sort_parse */


PUBLIC void close_ldap_connections(glob)
GLOB_STRUCT *glob;
{
    pLD_LIST ldlptr;

    for(ldlptr = glob->ld_list; ldlptr; ldlptr = ldlptr->next)
        ldap_unbind(ldlptr->ld);
}
/* end of function: close_ldap_connections */

PUBLIC LDAP *get_ldap_connection( host, port, glob )
char *host;
int port;
GLOB_STRUCT *glob;
{
    pLD_LIST ldlptr, *ldlhdl;
    LDAP *ld = NULL;
    int rc;

    for(ldlptr = glob->ld_list; ldlptr; ldlptr = ldlptr->next) {
        if ( !strcasecmp(ldlptr->host, host) && (ldlptr->port == port))
            ld = ldlptr->ld;

    }
    if (!ld) {

        if ( (ld = ldap_open( host, port )) == NULL )
            return(NULL);
        if ( (rc=ldap_simple_bind_s( ld, glob->webdn, glob->webpw ))
              != LDAP_SUCCESS )
            return(NULL);
        for(ldlhdl = &glob->ld_list; *ldlhdl; ldlhdl = &(*ldlhdl)->next)
            ;
        *ldlhdl = (pLD_LIST) ch_calloc(1, sizeof(LD_LIST));
        (*ldlhdl)->host = strdup(host);
        (*ldlhdl)->port = port;
        (*ldlhdl)->ld = ld;
    }
    return(ld);
}
/* end of function: get_ldap_connection */


PRIVATE void get_ref_attrs( ld1, dn, e1, glob )
LDAP *ld1;
char *dn;
LDAPMessage *e1;
GLOB_STRUCT *glob;
{
    pIND_ATTRS i_ptr;
    IND_ATTR_ARR *idx, **vnodes;
    int i, j, k, n;
    LDAP *ld;
    int rc;
    LDAPMessage *res, *e;
    struct timeval timeout;
    char **val, **val1;
    char ref_dn[BUFSIZ], ref_cnbuf[BUFSIZ], *ref_cn;


    for(i_ptr = glob->ind_attrs; i_ptr; i_ptr = i_ptr->next) {

        /* Function-Mode */
        if (i_ptr->ia_arr && (i_ptr->ia_arr[0].replace == 2))
            continue;

        if ( (val1 = ldap_get_values( ld1, e1, i_ptr->ref_attr )) == NULL )
            continue;

        for(idx = i_ptr->ia_arr, i=0; idx[i].key; i++){
            /* idx[i].key idx[i].replace idx[i].attr idx[i].host idx[i].port
               idx[i].base -- i_ptr->ref_attr */

            ld = get_ldap_connection( idx[i].host, idx[i].port, glob );

            timeout.tv_sec = glob->timeout;
            timeout.tv_usec = 0;

            for ( j = 0; val1[j] != NULL; j++ ) {
                if(strncasecmp(val1[j], idx[i].key, strlen(idx[i].key)))
                    continue;
                else {
                    strcpy(ref_cnbuf, val1[j]);
/*                    ref_cn = ref_cnbuf + strlen(idx[i].key);
*/
                      ref_cn = ref_cnbuf;
                }

                sprintf(ref_dn, "cn=%s,%s", ref_cn, idx[i].base);
                if ( (rc = ldap_search_st( ld, ref_dn, LDAP_SCOPE_BASE, 
                  "objectClass=*", NULL, 0, &timeout, &res )) != LDAP_SUCCESS )
                    continue;
                if ( (e = ldap_first_entry( ld, res )) == NULL )
                    return;
                val = ldap_get_values( ld, e, idx[i].attr );
                if(val[0] != NULL) {
                    if(!idx[i].e)
                        idx[i].e = ( LDAPMessage ** )
                            ch_malloc( 16 * sizeof(LDAPMessage *) );
                    for(n=0; idx[i].e[n];  n++)
                        ;
                    idx[i].e[n] = e;
                    idx[i].ld = ld;
                    vnodes = &glob->ind_attrs->valid_nodes;
                    if(!*vnodes)
                        *vnodes = (IND_ATTR_ARR *) 
                                   ch_malloc( 100 * sizeof(IND_ATTR_ARR *) );
                    for(k=0; (*vnodes)[k].key;  k++)
                        ;
                    if(j==0)
                        (*vnodes)[k] = idx[i];
                }
            }
        }
    }
}
/* end of function: get_ref_attrs */

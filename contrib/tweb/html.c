/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* html.c.....                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - HTML-Procedures                  *
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
*            May 28 1999                ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: html.c,v 1.6 1999/09/10 15:01:17 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "html.h"
#include "init_exp.h"
#include "support_exp.h"

#ifdef TUETEL
#include "tueTel_exp.h"
#endif

PUBLIC void print_attr(ld, fp, dn, label, tattr, e, flag, doNotShow, glob)
LDAP *ld;
FILE *fp;
char *dn;
char *label;
char *tattr;
LDAPMessage *e;
int  flag;
char *doNotShow;
GLOB_STRUCT *glob;
{
    char    **val;
    int    i, gotone = 0, firstline = TRUE, valid_label = FALSE;
    static char *nlabel;
    char    imageChar = 'J';
    char strbuf[BUFSIZ];
    int first_of_same = TRUE;

    nlabel = ldap_friendly_name(glob->friendlyfile, label, &fm); 

    if ( (val = ldap_get_values( ld, e, tattr )) == NULL )
        return;

        /* check if only 1 value and this one is in "doNotShow"
        if((doNotShow) && (val[1] == NULL) && (strcmp(val[0],doNotShow) == 0))
            return;
        */

    for ( i = 0; val[i]; i++ ) {

        sprintf(strbuf, "(%s)", glob->la[0]);
        if(!strncasecmp(val[i], strbuf, 4)) {
            strcpy(val[i], val[i]+4);
        }
        else if(val[i][0] == '(' && val[i][3] == ')' ) {
            val[i][0] = '\0';
            continue;
        }

        if (!doNotShow || strncasecmp (val[i], doNotShow, strlen (val[i])))
            valid_label = TRUE;
        else
            val[i][0] = '\0';
    }

    if(!valid_label) {

        ldap_value_free (val);
        return;

    }

    fprintf( fp, "\n<DT><B>%s</B><DD>", nlabel );

        /* handle photo-requests */
        if((flag == BMP) || (flag == JPEG2GIF) || (flag == JPEG)) {
            photof(fp, flag, imageChar, dn, tattr);
            return;
        }

    for ( i = 0; val[i] != NULL; i++ ) {

        char *vali;

        if(!*label ) first_of_same = FALSE;

        if(!*val[i]) continue;

        vali = char2html(val[i]);

        if (flag == URL) {
            urlf(fp, vali);

#ifdef TUE_TEL
        } else if (flag == TFUNCPERS) {
            tfuncpersf(fp, vali, ld, glob);
#endif

        } else if (flag == DYNAMICDN) {
            dynamicdnf(fp, vali, glob);

        } else if (flag == INDEXURL) {
            indexurlf(fp, vali, dn, glob);

        } else if (flag == URI) {
            urif(fp, vali, glob);

        } else if (flag == PGPKEY) {
            pgpkeyf(fp, vali, &firstline);

        } else if ( ( flag == MULTILINE ) || (strchr(vali, '$') && 
                                    strncmp(vali, "{T.61}", 6) != 0 )) {
            multilinef(fp, vali, &first_of_same, &firstline, &gotone, nlabel);

        } else if (flag == BOOLEAN) {
            booleanf(fp, val[i], glob);

        } else if (flag == DATE) {
            datef(fp, val[i]);

        } else if (flag == MAILTO) {
            mailtof(fp, val[i], vali);

        } else if (flag == HREF) {
            hreff(fp, val[i], vali, glob);

        } else if (flag == MOVETO) {
            movetof(fp, val[i], vali, glob);

        } else if (flag == PRE) {
            pref(fp, vali, glob);

        } else if (flag == HEADER) {
            headerf(fp, vali, glob);

        } else if (flag == REFERRAL) {
            referralf(fp, vali, glob);

#ifdef TUE_TEL
        } else if(flag == FAXTABLE) {
            faxtablef(fp, val, &firstline);
#endif

        } else
            defaultf(fp, vali, &firstline);
    }
    ldap_value_free( val );
}
/* end of function: print_attr */

PUBLIC void form_attr(ld, fp, label, tattr, e, multiline, add_empty, glob)
LDAP *ld;
FILE *fp;
char *label;
char *tattr;
LDAPMessage *e;
int  multiline;
int  add_empty;
GLOB_STRUCT *glob;
{
        char    **val, *s;
        char    buffer[1024];
        int     i, gotone = 0, line = 0;
        static char *nlabel;
        nlabel = ldap_friendly_name(glob->friendlyfile, label, &fm);
        if ( (val = ldap_get_values( ld, e, tattr )) == NULL ) {
        if (add_empty > 0)
            if(multiline)
                fprintf( fp, "<DT><B>%s</B><DD><TEXTAREA NAME=\"%s=\" ROWS=4 COLS=30></TEXTAREA><BR>\n", 
                                           nlabel, tattr);
            else
                        fprintf( fp, "<DT><B>%s</B><DD><INPUT NAME=\"%s=\" SIZE=30 ><BR>\n", 
                                           nlabel, tattr);
                return;
    }
        fprintf( fp, "\n<DT><B>%s</B><DD>", nlabel );
    buffer[0] ='\0';
        for ( i = 0; val[i] != NULL; i++ ) {
                if ( multiline ) {
                        char    *s, *p;
                    buffer[0] ='\0';
                        if ( gotone )
                                fprintf( fp, "<DT><B>%s</B><DD>", nlabel);
                        p = s = val[i];
                        while ( ( s = strchr( s, '$' )) ) {
                                *s++ = '\0';
                                while ( isspace( *s ) )
                                        s++;
                                if ( line == 0 ) {
                                        sprintf(buffer, "%s", p);
                                        line++;
                                } else {
                                        sprintf(buffer, "%s\n%s", buffer, p);
                    line++;
                                }
                                p = s;
                        }
            if (line++ == 0) {
                sprintf(buffer, "%s", p);
            } else {
                sprintf(buffer, "%s\n%s", buffer, p);
            }
            s = form_encode(buffer);
                fprintf( fp, 
                "<TEXTAREA NAME=\"%s=%s\" ROWS=%d COLS=30>%s</TEXTAREA><BR>\n", 
                                 tattr, s, line + 1, s);
                        /* fprintf( fp, "<INPUT NAME=\"%s=%s\" SIZE=30,%d VALUE=\"%s\"> <BR>\n", tattr, s, line + 1, s); */
                        gotone = 1;
                        line = 0;
                } else {
            s = form_encode(val[i]);
                        fprintf( fp, "<INPUT NAME=\"%s=%s\" SIZE=\"%d\" VALUE=\"%s\"><BR>\n", tattr, s, 
             strlen(val[i]) > 30 ? strlen(val[i]) + 3 : 30, s);
                }
        }
    if (add_empty > i)
        fprintf( fp, "<INPUT NAME=\"%s=\" SIZE=30 ><BR>\n", tattr);
        ldap_value_free( val );
}
/* end of function: form_attr */

PUBLIC void do_pict(ld, fp, dn, type, glob)
LDAP *ld;
FILE *fp;
char *dn;
int type;
GLOB_STRUCT *glob;
{
    int        rc, i;
    struct berval    **val;
    char            cmd[128], buffer[1024];
    char        *s;
    FILE        *op, *tp;
    LDAPMessage    *res, *e;
    struct stat    st;
        char            *cPtr, *ptype;
    char            *tattr;

    if ( (rc = ldap_search_s( ld, dn, LDAP_SCOPE_BASE, NULL,
        NULL, 0, &res )) != LDAP_SUCCESS ) {
        do_error(fp, rc, NOT_FOUND, glob);
        return;
    }

    if ( (e = ldap_first_entry( ld, res )) == NULL ) {
        do_error(fp, -2, SERVER_ERROR, glob);
        return;
    }

        /*
         *  old behaviour: use "photo" or "jpegPhoto" attribute
         *  as indicated by type-argument.
         */
        tattr = (type == 0 ? "photo" : "jpegPhoto");

        /* NEW: if attr is added to URL via "+" use that attribute */
        if( ( cPtr = strQuoteChr(dn,'+')) )
             tattr = ++cPtr;

    if ( (val = ldap_get_values_len( ld, e, tattr)) == NULL )
        return;

    s  = tmpnam( NULL );
    tp = fopen( s, "w+");

    if (type == 0) {  /* g3fax photo -> xbm */
        sprintf(cmd, "%s > %s", G3TOXBM, s);
        if (debug) fprintf(stderr, "%ld bytes FAX!! %s\n", 
                                     val[0]->bv_len, cmd);
                ptype = "x-xbitmap";
    } else if (type == 1) {    /* jpeg -> gif */
        sprintf(cmd, "%s > %s", JPEGTOGIF, s);
        if (debug) fprintf(stderr, "%ld bytes JPEG!! %s\n", 
                                     val[0]->bv_len, cmd);
                ptype = "gif";
    } else {              /* jpeg direct */
        sprintf(cmd, "cat > %s", s);
        if (debug) fprintf(stderr, "%ld bytes JPEG!! %s\n", 
                                     val[0]->bv_len, cmd);
                ptype = "jpeg";
           }

        
        
    if (http == 1) {
        fprintf(fp, "HTTP/1.0 %d OK<br>MIME-Version: 1.0<br>", 
                            DOCUMENT_FOLLOWS );
        fprintf(fp, "Content-type: image/%s<br>", ptype );
    }
        if (request == HEAD) {                
        fflush(fp);
        exit_tweb (1);                                   
        }                          
    if ((op = popen(cmd, "w")) == NULL ) 
         return;
    fwrite(val[0]->bv_val, val[0]->bv_len, 1, op);
    pclose(op);
    if (stat(s, &st) == 0 && http == 1) {
        fprintf(fp, "Content-length: %lu<br>", st.st_size);
        if (debug) fprintf(stderr, "Image size: %lu\n", st.st_size);
    }
    fprintf(fp, "<br>\n\n");

    while (( i = fread(buffer, 1, 1024, tp))) fwrite(buffer, 1, i, fp);
    fclose(tp);
    if (unlink(s) == -1) {
        if (debug) perror("Couldn't unlink temp image file");
    }
    fflush(fp);
}
/* end of function: do_pict */



PUBLIC void do_audio(ld, fp, dn, type, glob)
LDAP *ld;
FILE *fp;
char *dn;
int type;
GLOB_STRUCT *glob;
{
    int        rc;
    struct berval    **val;
    LDAPMessage    *res, *e;
    struct timeval    timeout;

    timeout.tv_sec = glob->timeout;
    timeout.tv_usec = 0;
    if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_BASE, NULL,
        NULL, 0, &timeout, &res )) != LDAP_SUCCESS ) {
        do_error(fp, rc, NOT_FOUND, glob);
        return;
    }

    if ( (e = ldap_first_entry( ld, res )) == NULL ) {
        do_error(fp, -2, SERVER_ERROR, glob);
        return;
    }
    if ( (val = ldap_get_values_len( ld, e, "audio" )) == NULL )
        return;
    if (http == 1) {
        fprintf(fp, "HTTP/1.0 %d OK\nMIME-Version: 1.0\nServer: %s\n", 
                  DOCUMENT_FOLLOWS, version);
        fprintf(fp, "Content-type:  audio/basic<P>Content-length: %ld\n\n", 
                  val[0]->bv_len);
    }
        if (request == HEAD) {                
        fflush(fp);
        exit_tweb (1);                                   
        }                          
    fwrite(val[0]->bv_val, val[0]->bv_len, 1, fp);
    fflush(fp);
}
/* end of function: do_audio */

PUBLIC void do_sizelimit(fp, type, glob)
FILE *fp;
int type;
GLOB_STRUCT *glob;

{
    fprintf(fp, type ? glob->la[21] : glob->la[20]);
}
/* end of function: do_sizelimit */

PUBLIC void do_error(fp, code, status, glob)
FILE *fp;
int code;
int status;
GLOB_STRUCT *glob;
{
    char *s = "";

           if (http == 1) {
        switch (status) {
              case BAD_REQUEST:      s = "Bad request"; break;
            case AUTH_REQUIRED:      s = "Authorization required"; break;
            case FORBIDDEN:      s = "Forbidden"; break;
            case NOT_FOUND:      s = "Not found"; break;
            case SERVER_ERROR:      s = "Server error"; break;
            case NOT_IMPLEMENTED: s = "Not implemented"; break;
            default:          s = "Unknown error";
        }

        fprintf(fp, "HTTP/1.0 %03d %s\nMIME-Version: 1.0\nContent-Type: text/html\n\n", status, s);
            }

        if (request == HEAD) {
        fflush(fp);
                   exit_tweb (1);
        }

        fprintf( fp, HTML_HEAD_TITLE, glob->la[22], glob->la[100]);
        fprintf( fp, "\n<H2>%s %s</H2>\n%s <P>%s <EM> %d: %s.</EM><P>%s<br></BODY></HTML>", glob->la[23], s, glob->la[24], glob->la[25], code, ldap_err2string( code ), glob->la[26] );
}
/* end of function: do_error */

PUBLIC void explain_error (fp, error, status, glob )
FILE *fp;
char *error;
int status;
GLOB_STRUCT *glob;

{
        char *s = "Unknown error";
        if (http == 1) {    
                switch (status) {
                case BAD_REQUEST:       s = "Bad request"; break;
                case AUTH_REQUIRED:     s = "Authorization required"; break;
                case FORBIDDEN:         s = "Forbidden"; break;   
                case NOT_FOUND:         s = "Not found"; break;
                case SERVER_ERROR:      s = "Server error"; break;              
                case NOT_IMPLEMENTED:   s = "Not implemented"; break;
                default:                s = "Unknown error";                  
                }                                                    
        fprintf(fp, "HTTP/1.0 %03d %s\n",status, s);
                fprintf(fp, "MIME-Version: 1.0\n");
                fprintf(fp, "Content-Type: text/html\n\n");
        }                                           
        if (request == HEAD) {                   
        fflush(fp);
                exit_tweb (1);               
        }
        fprintf( fp, HTML_HEAD_TITLE, glob->la[22], glob->la[100]);
    fprintf( fp, "<H2>%s: %s</H2>\n", glob->la[22], s);
    fprintf( fp, "%s</BODY>\n</HTML>", error);
}    
/* end of function: explain_error */

/* Make "Move upwards" Header */
PUBLIC void make_header (fp, dn, action, glob)
FILE *fp;
 char *dn;
int action;
GLOB_STRUCT *glob;
{
    char **s, **t, hrdn[1024];
    int  cnt, i, j;
    pGW_SWITCH_LINE gw_ptr;
    char url[BUFSIZ];

    if(glob->pull_down_menus) {
        make_header_pull_down(fp, dn, action, glob);
        return;
    }

    hrdn[0] = '\0';
    if ( strlen(dn) == 0)        /* the root */
        return;
    s = ldap_explode_dn( dn, 1 );
    t = ldap_explode_dn( dn, 0 );

    strcpy(url, "M");
    for(gw_ptr = glob->gw_switch->list; gw_ptr; gw_ptr = gw_ptr->next)
        if (!strcasecmp(gw_ptr->dn, "ROOT"))
            strcpy(url, gw_ptr->url);

    fprintf( fp, "<strong>%s </strong><MENU>\n<LI> <A HREF=\"%s\">%s</A>\n",
        glob->la[27], url, glob->la[77]);


    for (cnt=0; t[cnt]; cnt++);
    for (i = cnt - 1; i > 0 && s[i]; i--) {
        strcpy(hrdn, hex_encode(t[i]));
        for (j = i + 1; j < cnt ; j++) {
            strcat(hrdn, hex_encode(", "));
            strcat(hrdn,hex_encode(t[j]));
        }
        
        strcpy(url, "/");
        for(gw_ptr = glob->gw_switch->list; gw_ptr; gw_ptr = gw_ptr->next)
            if (!dn_cmp(hex_encode (gw_ptr->dn), hrdn))
                strcpy(url, url_complete(gw_ptr->url, hrdn, "M"));
        if(strcmp(url, "/"))
            fprintf( fp, "<LI> <A HREF=\"%s\">%s</A>\n",
                         url, i == cnt - 1 ? 
                         ldap_friendly_name( glob->friendlyfile, s[i], &fm ) : 
                         s[i]);
        else
            fprintf( fp, "<LI> <A HREF=\"%sM%s\">%s</A>\n",
                         url, hrdn, i == cnt - 1 ?
                         ldap_friendly_name( glob->friendlyfile, s[i], &fm ) :
                         s[i]);
            hrdn[0] = '\0';
    }
    fprintf( fp, "</MENU>\n");
    ldap_value_free(s);
    ldap_value_free(t);
}
/* end of function: make_header */

/* Make "Move upwards" Header with pull-down-menus*/
PUBLIC void make_header_pull_down (fp, dn, action, glob)
FILE *fp;
 char *dn;
int action;
GLOB_STRUCT *glob;
{
    char **s, **t, hrdn[1024];
    int  cnt, i, j;
    pGW_SWITCH_LINE gw_ptr;
    char url[BUFSIZ];

    hrdn[0] = '\0';
    if ( strlen(dn) == 0)        /* the root */
        return;
    s = ldap_explode_dn( dn, 1 );
    t = ldap_explode_dn( dn, 0 );

    strcpy(url, "M");
    for(gw_ptr = glob->gw_switch->list; gw_ptr; gw_ptr = gw_ptr->next)
        if (!strcasecmp(gw_ptr->dn, "ROOT"))
            strcpy(url, gw_ptr->url);

    fprintf( fp, "<FORM ACTION=\"/D\">\n");
    fprintf( fp, 
       "<INPUT TYPE=submit VALUE=\"%s\"> -&gt; <SELECT NAME=\"H\">\n",
                                   glob->la[27]);
    fprintf( fp, "<OPTION VALUE=\"%s\">%s\n", url, glob->la[77]);

    for (cnt=0; t[cnt]; cnt++);
    for (i = cnt - 1; i > 0 && s[i]; i--) {
        strcpy(hrdn, hex_encode(t[i]));
        for (j = i + 1; j < cnt ; j++) {
            strcat(hrdn, hex_encode(", "));
            strcat(hrdn,hex_encode(t[j]));
        }
        
        strcpy(url, "/");
        for(gw_ptr = glob->gw_switch->list; gw_ptr; gw_ptr = gw_ptr->next)
            if (!dn_cmp(hex_encode (gw_ptr->dn), hrdn))
                strcpy(url, url_complete(gw_ptr->url, hrdn, "M"));
        if(strcmp(url, "/"))
            fprintf( fp, "<OPTION VALUE=\"%s\" %s>%s\n", url,
                                i==1 ? "SELECTED" : "", i == cnt - 1 ?
                     ldap_friendly_name( glob->friendlyfile, s[i], &fm ) :s[i]);
        else
            fprintf( fp, "<OPTION VALUE=\"%sM%s\" %s>%s\n",
                     url, hrdn, i==1 ? "SELECTED" : "", i == cnt - 1 ? 
                     ldap_friendly_name( glob->friendlyfile, s[i], &fm ) :s[i]);
            hrdn[0] = '\0';
    }
    fprintf( fp, "</SELECT></FORM>\n");

    ldap_value_free(s);
    ldap_value_free(t);
}
/* end of function: make_header_pull_down */

PUBLIC char * url_complete (gwp_url, rdn, separator)
char *gwp_url, *rdn, *separator;
{
    static char url[BUFSIZ];
    char *strptr;

    strcpy(url, gwp_url);

    if(!strchr (gwp_url, '=')) {

        if (!strncasecmp (url, "http://", 7)) {

            if ( ( strptr = strchr (url+7, '/')) ) *(++strptr) = '\0';
            else strcat (url, "/");

        } else *url = '\0';

        sprintf (url, "%s%s%s", url, separator, rdn);

    }

    return(url);

}
/* end of function: url_complete */

PRIVATE void photof(fp, flag, imageChar, dn, tattr)
FILE *fp;
int  flag;
char    imageChar;
char *dn;
char *tattr;
{
    switch(flag) {
        case BMP     : imageChar = 'G'; break;
        case JPEG2GIF: imageChar = 'I'; break;
        case JPEG    : imageChar = 'J'; break;
    }
    fprintf( fp, "<IMG ALT=\"Photo\" SRC=\"%c%s\"+%s>\n",
               imageChar, hex_encode(dn), tattr);
}
/* end of function: photof */

PRIVATE void urlf(fp, vali)
FILE *fp;
char *vali;
{
    char *cp;

    if ((cp = strchr(vali, '$')) != NULL) {
        *cp++ = '\0';
        fprintf( fp, "%s%c\n", vali,
           (vali[0] ? ':' : ' '));
        fprintf(fp," <A HREF=\"%s\"> %s</A><BR>\n",
             cp, cp);
    } else
        fprintf( fp, "%s<BR>\n", vali);
}
/* end of function: urlf */

PRIVATE void dynamicdnf(fp, vali, glob)
FILE *fp;
char *vali;
GLOB_STRUCT *glob;
{
    fprintf(fp," <A HREF=\"%s/M%s\"> %s</A><BR>\n",

#ifdef TUE_TEL
               dn2server(vali, glob),
#else
               "",
#endif

               vali, vali);
}
/* end of function: dynamicdnf */

/* Allow href dn-lable flexible configuration via INDEXURL */
PRIVATE void indexurlf(fp, vali, entrydn, glob)
FILE *fp;
char *vali;
char *entrydn;
GLOB_STRUCT *glob;
{
    char *cp;
    char dnbuf[BUFSIZ], *strptr, **dn;
    char rulebuf[BUFSIZ], *disp_item;
    int arrsize, first;
    char entrydnbuf[BUFSIZ], dit_dnbuf[BUFSIZ];
    int index;

    if (((cp = strchr(vali, ' ')) != NULL) && glob->index_url) {

        *cp++ = '\0';
        index = atoi(cp);

        if ( index < 0 || index >= INDEX_RULE_SIZE )
            return;
        if (!glob->index_url->rarr[index].rule) {
            return;
        }

        /* case entrydn out of range */
        strcpy(entrydnbuf, entrydn);
        strcpy(dit_dnbuf, glob->index_url->rarr[index].dit_dn);
        dn_normalize(entrydnbuf);
        dn_normalize(dit_dnbuf);
        if(!dn_issuffix(entrydnbuf, dit_dnbuf)){
            fprintf(fp," <A HREF=\"%s\"> %s</A><BR>\n", vali, cp);
            return;
        }

        /* return if url doesn't contain cn= ( no dn ) */
        if(!(strptr = strstr(vali, "cn=")))
            return;
        strcpy(dnbuf, strptr);
        hex_decode(dnbuf);
        dn = ldap_explode_dn(dnbuf, 1);

        for(arrsize=0; dn[arrsize]; arrsize++)
            ;

        if(arrsize && glob->strip_pin)
            trimright(dn[0], " 1234567890");

        fprintf(fp," <A HREF=\"%s\">", vali);
        strcpy(rulebuf, glob->index_url->rarr[index].rule);
        first = 1;

        for(disp_item = strtok(rulebuf, ","); disp_item;
                                              disp_item = strtok(NULL, ",")) {
            if(abs(atoi(disp_item)) >= arrsize) continue;

            if(*disp_item == '-') {
                fprintf(fp,"%s%s", !first ? ", " : "",
                                   dn[arrsize + atoi(disp_item) - 1]);
            } else {
                fprintf(fp,"%s%s", !first ? ", " : "", dn[atoi(disp_item)]);
            }
            first = 0;
        }

        fprintf(fp,"</A><BR>\n");
    } else
        fprintf( fp, "%s<BR>\n", vali);
}
/* end of function: indexurlf */

PRIVATE void urif(fp, vali, glob)
FILE *fp;
char *vali;
GLOB_STRUCT *glob;
{
    char *cp;

    if(glob->gw_switch->dynamic && strstr(vali, "(gw"))
        return;
    if ((cp = strchr(vali, ' ')) != NULL) {
        *cp++ = '\0';
        fprintf(fp," <A HREF=\"%s\"> %s</A><BR>\n", vali, cp);
    } else
        fprintf( fp, "%s<BR>\n", vali);
}
/* end of function: urif */

/* function for ldap-referrals etc. */
PRIVATE void referralf(fp, vali, glob)
FILE *fp;
char *vali;
GLOB_STRUCT *glob;
{
    char *cp;

    if(glob->gw_switch->dynamic && strstr(vali, "(gw"))
        return;
    if ((cp = strchr(vali, ' ')) != NULL) {
        *cp++ = '\0';
        fprintf(fp," <A HREF=\"http://%s:%d/W%s\"> %s</A><BR>\n",
                glob->hostname, glob->webport, vali, cp);
    } else
        fprintf(fp," <A HREF=\"http://%s:%d/W%s\"> %s</A><BR>\n",
                glob->hostname, glob->webport, vali, vali);
}
/* end of function: referralf */

PRIVATE void pgpkeyf(fp, vali, firstline)
FILE *fp;
char *vali;
int *firstline;
{
    char    *s, *p;

    fprintf( fp, "<TT>\n");
    p = s = vali;
    while ( ( s = strstr( s, " $" )) ) {
        *s++ = '\0';   /*  delete BLANK  */
        *s++ = '\0';   /*  delete DOLLAR */
        while ( isspace( *s ) )
            s++;
        if ( *firstline == TRUE ) {
            fprintf( fp, "<DT>%s<BR>\n", p );
            *firstline = FALSE;
        } else if (!strncasecmp(p, "Version", 7)) {
            fprintf( fp, "%s<BR><BR>\n", p );
        } else {
            fprintf( fp, "%s<BR>\n", p );
        }
        p = s;
    }
    if ( *firstline == TRUE ) {
        fprintf( fp,"<DT>%s<BR>", p );
        *firstline = FALSE;
    } else {
        fprintf( fp, "%s\n", p );
    }
    fprintf( fp, "</TT>\n");
}
/* end of function: pgpkeyf */

PRIVATE void multilinef(fp, vali, first_of_same, firstline, gotone, nlabel)
FILE *fp;
char *vali;
int *first_of_same;
int *firstline;
int *gotone;
char *nlabel;
{
    char    *s, *p;

    if ( !*first_of_same && *gotone)
        fprintf( fp, "<BR>");
    if ( *gotone && *first_of_same)
        fprintf( fp, "<DT><B>%s</B><DD>", nlabel);
    else if (!*first_of_same)
        fprintf( fp, "<BR>");
    p = s = vali;

    /*  PATCH to process MULTILINE correctly:
        replace  strstr() instead of strchr(), in order not to missinterpret 
        DOLLAR in Text ; /KSp, 95/06/28
    */

    /*
    while ( s = strchr( s, '$' ) ) {
    */
    while ( ( s = strstr( s, " $" )) ) {
        *s++ = '\0';   /*  delete BLANK  */
        *s++ = '\0';   /*  delete DOLLAR */
        while ( isspace( *s ) )
            s++;

        /*
        if (dosyslog)
            syslog (LOG_INFO, "multiLineAttr: %s", p);
        */

        fprintf( fp, "%s<BR>\n", p );
        if ( *firstline == TRUE )
            *firstline = FALSE;
        p = s;
    }
    if ( *firstline ) {
        fprintf( fp, "%s<BR>\n", p );
    } else {
        fprintf( fp, "%s", p );
    }
    *gotone = 1;
    *firstline = FALSE;
    *first_of_same = FALSE;
}
/* end of function: multilinef */

PRIVATE void booleanf(fp, val_i, glob)
FILE *fp;
char *val_i;
GLOB_STRUCT *glob;
{
    if (!strcmp(val_i, "TRUE")) fprintf( fp, "%s<BR>\n", glob->la[78]);
    else fprintf( fp, "%s<BR>\n", glob->la[79]);
}
/* end of function: booleanf */

PRIVATE void datef(fp, val_i)
FILE *fp;
char **val_i;
{
    fprintf( fp, "%s<BR>\n", format_date(&val_i, "%A, %d-%h-%y %T GMT"));
}
/* end of function: datef */

PRIVATE void mailtof(fp, val_i, vali)
FILE *fp;
char *val_i;
char *vali;
{
   fprintf (fp, "<A HREF=\"mailto:%s\">%s</A><BR>\n", val_i, vali);
}
/* end of function: mailtof */

PRIVATE void hreff(fp, val_i, vali, glob)
FILE *fp;
char *val_i;
char *vali;
GLOB_STRUCT *glob;
{
    char    *ufn;
    char    op = 'R';

    ufn = friendly_dn( val_i, glob );
    fprintf( fp, "<A HREF=\"/%c%s\">%s</A><BR>\n", op,
        hex_encode(val_i), ufn ? ufn : vali);
    if ( ufn ) {
        free( ufn );
    }
}
/* end of function: hreff */

PRIVATE void movetof(fp, val_i, vali, glob)
FILE *fp;
char *val_i;
char *vali;
GLOB_STRUCT *glob;
{
    char    *ufn;
    char     op = 'M';

    ufn = friendly_dn( val_i, glob );
    fprintf( fp, "<A HREF=\"/%c%s\">%s</A><BR>\n", op,
        hex_encode(val_i), ufn ? ufn : vali);
    if ( ufn ) {
        free( ufn );
    }
}
/* end of function: movetof */


PRIVATE void headerf(fp, vali, firstline)
FILE *fp;
char *vali;
int *firstline;
{
    fprintf( fp, "<DT>");
    fprintf( fp, "<H1>");
    fprintf( fp,"%s", vali );
    fprintf( fp, "</H1>\n");
}
/* end of function: headerf */

PRIVATE void pref(fp, vali, firstline)
FILE *fp;
char *vali;
int *firstline;
{
    fprintf( fp, "<DT>");
    fprintf( fp, "<PRE>");
    fprintf( fp,"%s", vali );
    fprintf( fp, "</PRE>\n");
}
/* end of function: pref */

PRIVATE void defaultf(fp, vali, firstline)
FILE *fp;
char *vali;
int *firstline;
{
    if ( *firstline == TRUE ) {
        fprintf( fp,"%s", vali );
        *firstline = FALSE;
    } else {
        fprintf( fp, "<BR>\n%s", vali );
    }
}
/* end of function: defaultf */


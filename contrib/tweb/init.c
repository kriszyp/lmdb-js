/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* init.c.....                                                              *
*                                                                          *
* Function:..Initialisation-Routine for TWEB                               *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            July 21 1995                 Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            May 11 1999                ZZZZZ  DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: init.c,v 1.6 1999/09/10 15:01:17 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"
#include "init.h"


PUBLIC void getopts (argc, argv, glob)
int argc;
char **argv;
GLOB_STRUCT *glob;
{
    int            i;
    extern char        *optarg;
    char hname[BUFSIZ];
    struct hostent *hstruct;

    while ( (i = getopt( argc, argv, "P:ad:f:l:p:x:b:L:" )) != EOF ) {
        switch( i ) {
        case 'a':
            searchaliases = 0;
            break;
        case 'b':
            if(glob->basedn && glob->basedn->dn)
                free(glob->basedn->dn);
            glob->basedn->dn = strdup( optarg );
            break;
        case 'd':
            debug = atoi( optarg );
#ifdef LDAP_DEBUG
            ldap_debug = debug;
#else
            fprintf( stderr, 
                             "warning: ldap debugging requires LDAP_DEBUG\n" );
#endif
            break;

        case 'f':
            glob->filterfile = strdup( optarg );
            break;

        case 'l':
            dosyslog = cnvt_str2int( optarg, syslog_types, LOG_LOCAL3 );
            break;

        case 'p':
            glob->webport = atoi( optarg );
            break;

        case 'P':
            glob->ldapport = atoi( optarg );
            break;

        case 'x':
            if(glob->ldapd)
                free(glob->ldapd);
            glob->ldapd = str_tolower( strdup( optarg ));
            break;
        case 'L':
            break;
        default:
            usage(argv[0]);
        }
    }
    if ( (glob->myname = strrchr( argv[0], '/' )) == NULL )
        glob->myname = argv[0];
    else
        glob->myname++;

    if(!glob->hostname) {
        gethostname(hname, BUFSIZ);
        hstruct = gethostbyname(hname);
        glob->hostname = str_tolower( strdup( hstruct->h_name ));
    }

}
/* end of function: getopts */

PRIVATE void usage(name)
char    *name;
{
        fprintf(stderr, USAGE, name);
        exit( 1 );
}
/* end of function: usage */

PUBLIC void check (glob)
GLOB_STRUCT *glob;
{
    if(!glob->webport || !glob->ldapd || !glob->ldapport ||
                        !glob->basedn || !glob->sort) {
        fprintf(stderr,
"\nMissing must-attribute: webport || ldapd || ldapport || basedn->dn || sort\n!\n\n");
        exit(1);
    }

    if(glob->grant){
        trim(glob->grant, "|");
        glob->comp_grant = tweb_regcomp(glob->grant);
    }

    if(glob->refuse){
        trim(glob->refuse, "|");
        glob->comp_refuse = tweb_regcomp(glob->refuse);
    }

    if(glob->allow_string){
        trim(glob->allow_string, "|");
        glob->comp_allow = tweb_regcomp(glob->allow_string);
    }

    if(glob->deny_string){
        trim(glob->deny_string, "|");
        glob->comp_deny = tweb_regcomp(glob->deny_string);
    }

    if(!glob->webdn){
        glob->webdn   = "c=DE";
        if(glob->webpw) free(glob->webpw);
        glob->webpw   = NULL;
    }
    if(!glob->webdn2){
        glob->webdn2   = "c=BR";
        if(glob->webpw2) free(glob->webpw2);
        glob->webpw2   = NULL;
    }

    if(!glob->timeout)
        glob->timeout = DEFAULT_TIMEOUT;
    if(!glob->maxcount)
        glob->maxcount = DEFAULT_MAXCOUNT;

    if(!glob->subtree_search)
        glob->subtree_search =
                str2charray( "organization:organizationalUnit", ":");

    glob->cache_expire = glob->cache_expire % MAX_EXPIRE;

    f_test(glob);
    if(glob->sort) {
        pSORT_LINE s_ptr;
        pDISPLAY d_ptr;

        for(s_ptr = glob->sort; s_ptr; s_ptr = s_ptr->next)
            for(d_ptr = glob->display; d_ptr; d_ptr = d_ptr->next) {
                if(!strcmp(d_ptr->ocs, s_ptr->display_class)) {
                    s_ptr->display_class_ptr = d_ptr;
                    break;
                }
                if(!strcmp(d_ptr->ocs, "default"))
                    s_ptr->display_class_ptr = d_ptr;
            }
    }

    if( glob->ldapd && !strcmp(glob->ldapd, "x500-relay.uni-tuebingen.de") 
            && !strcmp(glob->lang, "0")) {
       fprintf( stderr,
            "\n\n\tYou missed to set LDAP-HOST and LDAP-PORT to\n\
             a machine of your own.\n\n\tPlease change as soon as \
             possible to avoid\n\
             overload of host x500-relay.uni-tuebingen.de !\n\n");
    }

}
/* end of function: check */

PUBLIC void init(argv, lang, glob)
char **argv;
char *lang;
GLOB_STRUCT *glob;
{
FILE *fp;
static char file[BUFSIZ];

    glob->argv0 = strdup(argv[0]);
    glob->gw_switch = (pGW_SWITCH) ch_calloc(1, sizeof(GW_SWITCH));
    glob->basedn = (BASEDN_LINE *) ch_calloc(1, sizeof(BASEDN_LINE));
    glob->basedn->dn = strdup("");
    glob->menu_filter = strdup("(& (objectClass=top)(!(objectClass=dSA)) )");

#ifdef RCINIT
    strcpy(file, RCINIT);
#else
    sprintf( file, "%s.rc", argv[0] );
#endif
    glob->acfilename = file;
    if(!(fp = fopen(file, "r"))) {
        fprintf(stderr, "\n\nATTENTION!!!\n\nCould not open file %s !\n", file);
        exit(1);
    }
    main_loop(fp, glob);
    fclose(fp);

#ifdef CONFINIT
    strcpy(file, CONFINIT);
#else
    sprintf( file, "%s.conf.%s", argv[0], glob->lang );
#endif
    glob->acfilename = file;
    if(!(fp = fopen(file, "r"))) {
        fprintf(stderr, "\n\nATTENTION!!!\n\nCould not open file %s !\n", file);
        exit(1);
    }
    main_loop(fp, glob);
    fclose(fp);
    return;
}
/* end of function: init */

#define  STRINGP(x)   ((x) ? (x) : "(NULL)")

PUBLIC void output(fp, glob, html_flag)
FILE *fp;
GLOB_STRUCT *glob;
int html_flag;
{
    pDISPLAY d_ptr;
    pSEARCH_ONLY_LINE so_ptr;
    pGW_SWITCH_LINE gw_ptr;
    pSORT_LINE s_ptr;
    pDISPLAY_LINE dis_ptr;
    pMODIFY_LINE mod_ptr;
    pMODIF m_ptr;
    pCACHING_TERMS_LINE ca_ptr;
    pIND_ATTRS i_ptr;
    IND_ATTR_ARR *idx;
    pTABLE_DISPLAY ta_ptr;
    pFORM_BUTTON fo_ptr;
    int i;
    char hb[BUFSIZ], he[BUFSIZ], li[BUFSIZ], lb[BUFSIZ], le[BUFSIZ];

    strcpy(lb, html_flag ? "<UL>" : "");
    strcpy(le, html_flag ? "</UL>" : "");
    strcpy(li, html_flag ? "<LI>" : "");
    strcpy(hb, html_flag ? "</UL><B>" : "");
    strcpy(he, html_flag ? "</B><UL>" : "");

/*for(i=0; glob->sort_attribs[i]; i++)
    fprintf(fp,"%s<p>\n", glob->sort_attribs[i]);
*/

    fprintf(fp,
        "%s\n\n\n###############CONFIGURATION-DISPLAY###############\n\n%s",
        html_flag ? "<B>" : "", he);
    fprintf(fp, "\n%s\n\n%s", version, html_flag ? "<p>" : "");
/*    fprintf(fp, "%s\n%s\n\n%s", html_flag ? "<B>" : "", version, he);
*/

    fprintf(fp, "%sWEBDN%s%s %s\n", hb, he, li, STRINGP( glob->webdn ));
    fprintf(fp, "%sWEBDN2%s%s %s\n", hb, he, li, STRINGP( glob->webdn2 ));
    if(!html_flag){
        fprintf(fp, "WEBPW: %s\n", STRINGP( glob->webpw ));
        fprintf(fp, "WEBPW2: %s\n", STRINGP( glob->webpw2 ));
    }
    fprintf(fp, "%sTWEBHOST%s%s %s:%d\n", hb, he, li, STRINGP( glob->hostname ),
            glob->virtualport ? glob->virtualport : glob->webport);
    fprintf(fp, "%sWEBPORT%s%s %d\n", hb, he, li, glob->webport);
    fprintf(fp, "%sTIMEOUT%s%s %d\n", hb, he, li, glob->timeout);
    fprintf(fp, "%sLDAPD%s%s %s\n", hb, he, li, STRINGP( glob->ldapd ));
    fprintf(fp, "%sLDAPPORT%s%s %d\n\n", hb, he, li, glob->ldapport);
    fprintf(fp, "%sETCDIR%s%s %s\n", hb, he, li, STRINGP( glob->etcdir ));
    fprintf(fp, "%sHELPFILE%s%s %s\n", hb, he, li, STRINGP( glob->helpfile ));
    fprintf(fp, "%sFILTERFILE%s%s %s\n", hb, he, li,
        STRINGP( glob->filterfile ));
    fprintf(fp, "%sFRIENDLYFILE%s%s %s\n", hb, he, li,
        STRINGP( glob->friendlyfile ));
    fprintf(fp, "%sHEADER%s%s %s\n", hb, he, li, STRINGP( glob->header ));
    fprintf(fp, "%sFOOTER%s%s %s\n", hb, he, li, STRINGP( glob->footer ));
    fprintf(fp, "%sGRANT%s%s %s\n", hb, he, li, STRINGP( glob->grant ));
    fprintf(fp, "%sREFUSE%s%s %s\n", hb, he, li, STRINGP( glob->refuse ));

    fprintf(fp, "%s\nPULL-DOWN-MENUS%s%s %s\n",
        hb, he, li, glob->pull_down_menus?"YES":"NO");
    fprintf(fp, "%s\nDISP-SEA-RDN%s%s %s\n",
         hb, he, li, glob->disp_sea_rdn?"YES":"NO");
    fprintf(fp, "%s\nNO-PROXY%s%s %s\n", hb, he, li, glob->no_proxy?"YES":"NO");
    fprintf(fp, "%s\nALLOW-PROXY%s\n%s", hb, he, li);
    for(i = 0; glob->allow_proxy && glob->allow_proxy[i]; i++) 
        fprintf(fp, "%s:", glob->allow_proxy[i]);

    fprintf(fp, "%sALLOW-STRING%s%s %s\n", hb, he, li,
        STRINGP( glob->allow_string ));
    fprintf(fp, "%sDENY-STRING%s%s %s\n", hb, he, li,
        STRINGP( glob->deny_string ));
    fprintf(fp, "%sALLOW-MSG%s%s %s\n", hb, he, li, STRINGP( glob->allow_msg ));
    fprintf(fp, "%s\nBASEDN%s%s \t%s\t%s\t%s\n", hb, he, li,
         STRINGP( glob->basedn->dn ), STRINGP( glob->basedn->head ),
        STRINGP( glob->basedn->foot ));
/*    fprintf(fp, "%s\nBASEDNARRAY%s%s \t%s\t%s\n", hb, he, li, glob->basedn->dnarray[0], glob->basedn->dnarray[1]); */
    fprintf(fp, "%s\nMAXCOUNT%s%s %d\n", hb, he, li, glob->maxcount);
    if (glob->comrefuse)
        fprintf(fp, "%s\nCOMREFUSE%s%s %d\t%d\t%d\t%d\t%lu\t%s\n",
                    hb, he, li, glob->comrefuse->tmin, glob->comrefuse->tdiff,
                    glob->comrefuse->maxAccept, glob->comrefuse->suspendCycle,
                    glob->comrefuse->statCycle,
                    STRINGP( glob->comrefuse->statFile ));
    fprintf(fp, "%s\nMAX-PERSON%s%s %d\t%s\t%s\n", hb, he, li,
         glob->max_person, glob->strict?"STRICT":"",
         glob->no_browse?"NO-BROWSE":"");
    fprintf(fp, "%s\nLEGAL%s%s %s %s\n", hb, he, li, glob->legal?"YES":"NO",
                 glob->legal_top ? "ON-TOP" : "");
/*    fprintf(fp, "%s\nSHOW-DEFOC%s%s %s\n", hb, he, li, glob->show_defoc?"YES":"NO");
*/

#ifdef AMBIXGW
    fprintf(fp, "%s\nSELBSTEINTRAG%s\n", hb, he);
    for(i = 0; i<9; i++) 
        if (glob->selbsteintrag[i])
            fprintf(fp, "%s\t%s\n", li, glob->selbsteintrag[i]);
#endif

    fprintf(fp, "%s\nSTRIP-PIN%s%s %s\n", hb, he, li,
        STRINGP( glob->strip_pin ));
    fprintf(fp, "%s\nPREFER-REF-URIS%s%s %s\n", hb, he, li,
         glob->prefer_ref_uris?"YES":"NO");
    fprintf(fp, "%s\nSTRICT-BASEDN%s%s %s\n", hb, he, li,
         glob->strict_basedn?"YES":"NO");
    fprintf(fp, "%s\nNO-SHOW-RDN%s%s %s\n\n", hb, he, li,
        STRINGP( glob->no_show_rdn ));
    fprintf(fp, "%s\nNO-MODIFY%s%s %s\n\n", hb, he, li,
        STRINGP( glob->no_modify ));

#ifdef TUE_TEL
    fprintf(fp, "%sPHONEWORLD%s%s %s\n", hb, he, li,
        STRINGP( glob->phoneworld ));
#endif

    fprintf(fp, "%s\nLANGUAGE%s\n", hb, he);
    for(i = 0; glob->language[i]; i++) 
        fprintf(fp, "%s\t%s\n", li, glob->language[i]);

    fprintf(fp, "%s\nCACHE-EXPIRE-DEFAULT%s%s %d\n", hb, he, li,
         glob->cache_expire);
    fprintf(fp, "%s\nCACHING-TERMS%s\n", hb, he);
    for(ca_ptr = glob->caching_terms; ca_ptr; ca_ptr = ca_ptr->next) {
        fprintf(fp, "%s\t%d\t%s\t%s\t%s\n", li, ca_ptr->time,
         STRINGP( ca_ptr->access_type ), ca_ptr->rdn_oc ? "RDN" : "OC",
        STRINGP( ca_ptr->pattern ));
    }

#ifdef TUE_TEL
    if(glob->ton_urls) {
        fprintf(fp, "%s\nTON-URLS%s\n", hb, he);
        fprintf(fp, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",li,
       STRINGP( glob->ton_urls->attribute ),
                 STRINGP( glob->ton_urls->rdn_attr ),
        STRINGP( glob->ton_urls->redirect ),
                 STRINGP( glob->ton_urls->x_disp ),
        STRINGP( glob->ton_urls->base ),
                 glob->ton_urls->admin?"ADMIN":
                       glob->ton_urls->pass_oc? glob->ton_urls->pass_oc : "");
    }
#endif
    if(glob->ip_refuse) {
        fprintf(fp, "%s\nIP-REFUSE%s\n", hb, he);
        fprintf(fp, "%s\t%s\t%d\n",li,
       STRINGP( glob->ip_refuse->dat_file ), glob->ip_refuse->rereadcycle);
    }

    fprintf(fp, "%s\nSEARCH-ONLY%s\n", hb, he);
    for(so_ptr = glob->search_only; so_ptr; so_ptr = so_ptr->next) {
        fprintf(fp, "%s\t%s\t%s\t%s\n", li, STRINGP( so_ptr->dn ),
         STRINGP( so_ptr->head ), STRINGP( so_ptr->foot ));
    }

    fprintf(fp, "%s\nSUBTREE-SEARCH%s\n%s", hb, he, li);
    for(i = 0; glob->subtree_search && glob->subtree_search[i]; i++) 
        fprintf(fp, "%s:", glob->subtree_search[i]);

    if(glob->index_url) {
        fprintf(fp, "%s\nINDEX-URL%s\n", hb, he);
        fprintf(fp, "%s\t%s\t%d\n", li, STRINGP( glob->index_url->dat_file ),
                glob->index_url->rereadcycle );
    }

#ifdef TUE_TEL
    if(glob->dit_config) {
        fprintf(fp, "%s\nDIT-CONFIG%s\n", hb, he);
        fprintf(fp, "%s\t%s\t%s\t%s\n", li, STRINGP( glob->dit_config->attr ),
                STRINGP( glob->dit_config->fetch_dn ),
                glob->dit_config->not_browse ? "NOT-BROWSE" : "");
    }
#endif

    fprintf(fp, "%s\nDYNAMIC-GW%s%s %s\n", hb, he, li,
         glob->gw_switch->dynamic?"YES":"NO");
    fprintf(fp, "%s\nGW-SWITCH%s\n", hb, he);
    for(gw_ptr = glob->gw_switch->list; gw_ptr; gw_ptr = gw_ptr->next) {
        fprintf(fp, "%s\t%s\t%s\n", li, STRINGP( gw_ptr->dn ),
        STRINGP( gw_ptr->url ));
    }

    fprintf(fp, "%s\nSORT%s\n", hb, he);
    for(s_ptr = glob->sort; s_ptr; s_ptr = s_ptr->next) {
        fprintf(fp, "%s\t%s\t%s\t%d\t%s\t%s\n", li,
        STRINGP( s_ptr->object_class ),
         STRINGP( s_ptr->label ), s_ptr->priority,
        STRINGP( s_ptr->display_class ), STRINGP( s_ptr->sort_attr ));
    }

    fprintf(fp, "%s\nTABLES%s\n", hb, he);
    for(ta_ptr = glob->tables; ta_ptr; ta_ptr = ta_ptr->next) {
        fprintf(fp, "%s\t%s\t%s\t%s\t%s\n", li, ta_ptr->allow ? "ALLOW" : "ALL",
         STRINGP( ta_ptr->select_oc ), STRINGP( ta_ptr->button_label ),
        STRINGP( ta_ptr->dn_extension ));
    }

    fprintf(fp, "%s\nFORM-BUTTON%s\n", hb, he);
    for(fo_ptr = glob->form_button; fo_ptr; fo_ptr = fo_ptr->next) {
        fprintf(fp, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", li,
            fo_ptr->read_menu ? "READ" : "MENU",
            STRINGP( fo_ptr->object_class ), STRINGP( fo_ptr->method ),
            STRINGP( fo_ptr->script_url ), STRINGP( fo_ptr->text ),
            STRINGP( fo_ptr->dn_name ), STRINGP( fo_ptr->form_name ),
            STRINGP( fo_ptr->button_label ));
    }

    fprintf(fp, "%s\nINDIRECT-ATTRS%s", hb, he);
    for(i_ptr = glob->ind_attrs; i_ptr; i_ptr = i_ptr->next) {
        fprintf(fp, "%s %s\n%s", li, STRINGP( i_ptr->ref_attr ), lb );
        for(idx = i_ptr->ia_arr, i=0; idx[i].key; i++)
            fprintf(fp, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n", li, idx[i].key,
             idx[i].replace == 2 ? "FUNCTION" : idx[i].replace ? "REPLACE" :
             "APPEND", STRINGP( idx[i].attr ), STRINGP( idx[i].host ),
        idx[i].port, STRINGP( idx[i].base ));
        fprintf(fp, le);
    }
    fprintf(fp, le);

    fprintf(fp, "%s\nMODIFY%s", hb, he);
    for(m_ptr = glob->modify; m_ptr; m_ptr = m_ptr->next) {
        fprintf(fp, "%s %s\n%s", li, STRINGP( m_ptr->ocs ), lb );
        for(mod_ptr = m_ptr->modattr; mod_ptr; mod_ptr = mod_ptr->next)
            fprintf(fp, "%s\t%s\t%s\t%d\n", li, STRINGP( mod_ptr->attribute ),
         STRINGP( mod_ptr->label ), mod_ptr->count);
    }
    fprintf(fp, le);

    fprintf(fp, "%s\nDISPLAY-OBJECT%s", hb, he);
    for(d_ptr = glob->display; d_ptr; d_ptr = d_ptr->next) {
        fprintf(fp, "%s\n\n %s\n%s", li, STRINGP( d_ptr->ocs) , lb );
        fprintf(fp, "%sFIRST-PAGE:\n%s", li, lb);
        for(dis_ptr = d_ptr->first_page; dis_ptr; dis_ptr = dis_ptr->next)
            fprintf(fp, "%s\t%s\t%s\t%s\n", li, STRINGP( dis_ptr->attribute ),
         STRINGP( dis_ptr->label ), STRINGP( dis_ptr->type ));
        fprintf(fp, "%s%sSECOND-PAGE:\n%s", le, li, lb);
        for(dis_ptr = d_ptr->second_page; dis_ptr; dis_ptr = dis_ptr->next)
            fprintf(fp, "%s\t%s\t%s\t%s\n", li, STRINGP( dis_ptr->attribute ),
         STRINGP( dis_ptr->label ), STRINGP( dis_ptr->type ));
        fprintf(fp, "%s%s", le, le);
    }
    fprintf(fp, le);
}
/* end of function: output */

PRIVATE void main_loop(fp,glob)
FILE *fp;
GLOB_STRUCT *glob;
{
FILELINE inLine;
extern PARSE_ENTRY parse_table[];

    while(do_readf(&inLine, fp)){
        parse(&inLine, parse_table, glob, 0);
    }
}
/* end of function: main_loop */

PUBLIC int do_readf(inLine, fp)
FILE *fp;
FILELINE *inLine;
{
static FILE *fo;
static int lineCount = 0;

    if(fp)
        fo = fp;

    do {
        char *comment;

        if(!fgets(inLine->value, BUFSIZ-1, fo)){
            lineCount = 0;
            return(0);
        }
        lineCount++;
        if( (comment = strchr(inLine->value, '#')) )
            *comment = '\0';
        trim(inLine->value, " \t\n");
    } while(!*inLine->value);

    inLine->count = lineCount;
/*    printf("%d: %s\n", inLine->count, inLine->value);
*/
    return (inLine->count);
}
/* end of function: do_readf */

PRIVATE int parse(inLine, p_table, glob, level)
FILELINE *inLine;
PARSE_ENTRY *p_table;
GLOB_STRUCT *glob;
int level;
{
int lineCount = inLine->count;

    while(1){
        switch(parse2(inLine, p_table, glob, level)){
            case NOTOK:
                printf("Error in init-file line %d:\n%s\n ", inLine->count, inLine->value);
                exit(1);
            case DONE:
                if(lineCount == inLine->count)
                    return (DONE);
                else
                    lineCount = inLine->count;
                break;
            default:
                return (OK);
        }
    }
}
/* end of function: parse */

PRIVATE int parse2(inLine, p_table, glob, level)
FILELINE *inLine;
PARSE_ENTRY *p_table;
GLOB_STRUCT *glob;
int level;
{
PARSE_ENTRY *disp;
char keyWord[BUFSIZ];

    sscanf(inLine->value, "%s", keyWord);
    str_toupper( keyWord );
    for(disp=p_table; disp->keyWord; disp++) {
        if(!strcmp(keyWord, disp->keyWord)){
            return ((*disp->keyFunc)(inLine, disp, glob, level));
        }
    }
    return (level?DONE:NOTOK);
}
/* end of function: parse2 */

PUBLIC int get_str_param(inLine, str, glob, lower)
FILELINE *inLine;
char **str;
GLOB_STRUCT *glob;
int          lower;
{
char tmp[4*BUFSIZ];

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    }else
        if (sscanf(inLine->value, "%*s%s", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    do {
        if(*str) {
            *str = realloc(*str, strlen(*str) + strlen(tmp) +1 );
            strcat(*str, lower ? str_tolower( tmp ) : tmp );
        } else {
            *str = strdup( lower ? str_tolower( tmp ) : tmp );
        }
            
        if(!do_readf(inLine, NULL))
            return (OK);

        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        }else
            if (sscanf(inLine->value, "%s", tmp) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

     } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');

    return (DONE);
}
/* end of function: get_str_param */

PRIVATE int get_int_param(inLine, integer, glob)
FILELINE *inLine;
int *integer;
GLOB_STRUCT *glob;
{
char tmp[BUFSIZ];

    if (sscanf(inLine->value, "%*s%s", tmp) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    *integer = atoi(tmp);
    return (OK);
}
/* end of function: get_int_param */


PRIVATE int webdn(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->webdn, glob, 0));
}
/* end of function: webdn */

PRIVATE int webpw(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->webpw, glob, 0));
}
/* end of function: webpw */

PRIVATE int webdn2(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->webdn2, glob, 0));
}
/* end of function: webdn2 */

PRIVATE int webpw2(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->webpw2, glob, 0));
}
/* end of function: webpw2 */


PRIVATE int webport(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_int_param(inLine, &glob->webport, glob));
}
/* end of function: webport */

PRIVATE int timeout(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_int_param(inLine, &glob->timeout, glob));
}
/* end of function: timeout */

PRIVATE int hostname(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char hostname[BUFSIZ];
char *virtualport;

    if (sscanf(inLine->value, "%*s%s", hostname) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    if( ( virtualport = strchr(hostname, ':')) ) {
        *virtualport++ = '\0';
        glob->virtualport = atoi( virtualport );
    }
    glob->hostname = strdup( hostname );
    return (OK);
}
/* end of function: hostname */

PRIVATE int ldapd(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->ldapd, glob, 1));
}
/* end of function: ldapd */

PRIVATE int ldapportf(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_int_param(inLine, &glob->ldapport, glob));
}
/* end of function: ldapportf */

PRIVATE int etcdir(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->etcdir, glob, 0));
}
/* end of function: etcdir */

PRIVATE int filterfilef(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->filterfile, glob, 0));
}
/* end of function: filterfile */

PRIVATE int helpfilef(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->helpfile, glob, 0));
}
/* end of function: helpfile */

PRIVATE int friendlyfilef(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->friendlyfile, glob, 0));
}
/* end of function: friendlyfile */

PRIVATE int index_url(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char dat_file[BUFSIZ];
    char rereadcycle[BUFSIZ];

    if (sscanf(inLine->value, "%*s%s%s", dat_file, rereadcycle) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n",
                glob->acfilename, inLine->count, inLine->value);

    glob->index_url  = (INDEX_URL *) ch_calloc(1, sizeof(INDEX_URL));
    glob->index_url->dat_file = strdup( dat_file );
    glob->index_url->rereadcycle = atoi(rereadcycle);

    get_index_url_rules(glob);

    return (OK);
}  /*  index_url  */

PUBLIC void get_index_url_rules(glob)
GLOB_STRUCT *glob;
{
char index[BUFSIZ];
char rule[BUFSIZ];
char dit_dn[BUFSIZ];
FILE *dfp;
char  inLine[BUFSIZ];
int idx;

    if ( !glob->index_url || !glob->index_url->dat_file )
        return;
    if(!(dfp = fopen(glob->index_url->dat_file, "r")))
        return;

    for ( idx = 0; idx < INDEX_RULE_SIZE; idx++ ) {
        free( glob->index_url->rarr[idx].rule );
        free( glob->index_url->rarr[idx].dit_dn );
    }

    while(fgets(inLine, BUFSIZ-1, dfp)) {

        if(strchr(inLine, '"')) {
            if (sscanf(inLine, "%s%s%*[^\"]\"%[^\"]\"",
                                    index, rule, dit_dn) < 1)
                syslog (LOG_INFO, "Error in index_url-file");
        } else {
            if (sscanf(inLine, "%s%s%s",
                                   index, rule, dit_dn) < 1)
                syslog (LOG_INFO, "Error in index_url-file");
        }
        idx = atoi(index);
        if ( idx < 0 || idx >= INDEX_RULE_SIZE )
            continue;
        glob->index_url->rarr[idx].rule = str_tolower( strdup( rule ));
        glob->index_url->rarr[idx].dit_dn = strdup( dit_dn );
    }
    fclose( dfp );
}
/* end of function: get_index_url_rules */

PUBLIC void re_read_index_url_rules( glob )
GLOB_STRUCT   *glob;
{
	static int index_url_rules_reload = 0;

	if ( glob->index_url && glob->index_url->rereadcycle && !( ++index_url_rules_reload % glob->index_url->rereadcycle )) {
		get_index_url_rules( glob );
	}

}  /*  re_read_index_url_rules  */


PRIVATE int allow_proxy(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    }else
        if (sscanf(inLine->value, "%*s%s", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    glob->allow_proxy = str2charray( str_tolower(tmp), ":");
    return (OK);
}
/* end of function: allow_proxy */

PRIVATE int subtree_search(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    }else
        if (sscanf(inLine->value, "%*s%s", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    glob->subtree_search = str2charray( tmp, ":");
    return (OK);
}
/* end of function: subtree_search */

PRIVATE int grant(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->grant, glob, 1));
}
/* end of function: grant */

PRIVATE int refuse(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->refuse, glob, 1));
}
/* end of function: refuse */

PRIVATE int allow_string(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->allow_string, glob, 1));
}
/* end of function: allow_string */

PRIVATE int deny_string(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->deny_string, glob, 1));
}
/* end of function: deny_string */


PRIVATE int show_defoc(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->show_defoc = 1;
    return (OK);
}
/* end of function: show_defoc */

PRIVATE int max_person(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];
char tmp2[BUFSIZ];
char tmp3[BUFSIZ];

    if (sscanf(inLine->value, "%*s%s%s%s", tmp, tmp2, tmp3) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    glob->max_person = atoi(tmp);
    glob->strict = (!strcasecmp (tmp2, "strict") || !strcasecmp (tmp3, "strict")) ? TRUE : FALSE;
    glob->no_browse = (!strcasecmp (tmp2, "no-browse") || !strcasecmp (tmp3, "no-browse")) ? TRUE : FALSE;

    return (OK);
}
/* end of function: max_person */

PRIVATE int comrefuse(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char tmp[BUFSIZ];
    char tmp2[BUFSIZ];
    char tmp3[BUFSIZ];
    char tmp4[BUFSIZ];
    char tmp5[BUFSIZ];
    char tmp6[BUFSIZ];

    if (sscanf(inLine->value, "%*s%s%s%s%s%s%s",
                      tmp, tmp2, tmp3, tmp4, tmp5, tmp6) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    comRefuseP = glob->comrefuse = 
                           (COMREFUSE *) ch_calloc(1, sizeof(COMREFUSE));
    glob->comrefuse->tmin = atoi(tmp);
    glob->comrefuse->tdiff = atoi(tmp2) - glob->comrefuse->tmin;
    glob->comrefuse->maxAccept = atoi(tmp3);
    glob->comrefuse->suspendCycle = -1 * atoi(tmp4);
    glob->comrefuse->statCycle = (time_t) atol (tmp5);
    sprintf (tmp6, "%s.%s-%d", tmp6, glob->lang, (int) getpid());
    glob->comrefuse->statFile = strdup (tmp6);

    return (OK);
}
/* end of function: comrefuse */

PRIVATE int display(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];
pDISPLAY *d_ptr;

    for(d_ptr = &glob->display; *d_ptr; d_ptr = &(*d_ptr)->next)
        ;
    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    *d_ptr = (pDISPLAY) ch_calloc(1, sizeof(DISPLAY));
    (*d_ptr)->ocs = str_tolower( strdup( tmp ));
    if(strcmp(tmp, "default"))
        glob->default_display_type = *d_ptr;
    if(!do_readf(inLine, NULL))
                        return (OK);
    return (parse(inLine,disp->subTable, glob, ++level));
}
/* end of function: display */

PRIVATE int basednf(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char dn[BUFSIZ];
char head[BUFSIZ];
char foot[BUFSIZ];

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]\"%s%s", dn, head, foot) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
     } else
        if (sscanf(inLine->value, "%*s%s%s%s", dn, head, foot) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
	if ( !strcasecmp( dn, "ROOT" )) *dn = '\0';
    glob->basedn->dn = strdup( dn );
    glob->basedn->dnarray = dn2charray( dn );
    glob->basedn->head = strdup(head);
    glob->basedn->foot = strdup(foot);
    return (OK);
}
/* end of function: basednf */

PRIVATE int search_only(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char dn[BUFSIZ];
char head[BUFSIZ];
char foot[BUFSIZ];
pSEARCH_ONLY_LINE *so_ptr;

    so_ptr = &glob->search_only;
    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]\"%s%s", dn, head, foot) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%s%s", dn, head, foot) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    do {
        *so_ptr = (pSEARCH_ONLY_LINE) ch_calloc(1, sizeof(SEARCH_ONLY_LINE));
        (*so_ptr)->dn = str_tolower( strdup( dn ));
        (*so_ptr)->head = strdup(head);
        (*so_ptr)->foot = strdup(foot);
        so_ptr = &(*so_ptr)->next;
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%*[^\"]\"%[^\"]\"%s%s", dn, head, foot) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s", dn, head, foot) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
    return (DONE);
}
/* end of function: search_only */

PRIVATE int dynamic_gw(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->gw_switch->dynamic = 1;
    return (OK);
}
/* end of function: dynamic_gw */

PRIVATE int caching_terms(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char time[BUFSIZ];
char access_type[BUFSIZ];
char rdn_oc[BUFSIZ];
char pattern[BUFSIZ];
pCACHING_TERMS_LINE *ca_ptr;

    ca_ptr = &glob->caching_terms;

    if (sscanf(inLine->value, "%*s%s%s%s%s", 
               time, access_type, rdn_oc, pattern) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", 
                glob->acfilename, inLine->count, inLine->value);
    do {
        *ca_ptr = (pCACHING_TERMS_LINE) ch_calloc(1, sizeof(CACHING_TERMS_LINE));
        (*ca_ptr)->time = atoi(time);
        (*ca_ptr)->access_type = str_toupper(strdup(trim (access_type,WSPACE)));
        (*ca_ptr)->rdn_oc = !strncasecmp(rdn_oc, "RDN", 3) ? 1 : 0;
        (*ca_ptr)->pattern = str_tolower(strdup(trim (pattern, WSPACE)));
        ca_ptr = &(*ca_ptr)->next;
        if(!do_readf(inLine, NULL))
                        return (OK);
        if (sscanf(inLine->value, "%s%s%s%s", 
                   time, access_type, rdn_oc, pattern) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n",
                    glob->acfilename, inLine->count, inLine->value);
    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
    return (DONE);
}
/* end of function: caching_terms */

PRIVATE int gw_switch(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char dn[BUFSIZ];
char url[BUFSIZ];
pGW_SWITCH_LINE *gw_ptr;

        for(gw_ptr = &glob->gw_switch->list; *gw_ptr; gw_ptr = &(*gw_ptr)->next)
                ;
    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]\"%[\40-\177]", dn, url) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%[\40-\177]", dn, url) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    do {
        *gw_ptr = (pGW_SWITCH_LINE) ch_calloc(1, sizeof(GW_SWITCH_LINE));
        (*gw_ptr)->dn = str_tolower( strdup( dn ));
        (*gw_ptr)->url = strdup(trim (url, WSPACE));
        gw_ptr = &(*gw_ptr)->next;
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%*[^\"]\"%[^\"]\"%[\40-\177]", dn, url) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%[\40-\177]", dn, url) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
    return (DONE);
}
/* end of function: gw_switch */

PRIVATE int table_disp(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char allow[BUFSIZ];
    char select_oc[BUFSIZ];
    char button_label[BUFSIZ];
    char dn_extension[BUFSIZ];
    pTABLE_DISPLAY *ta_ptr;

        for(ta_ptr = &glob->tables; *ta_ptr; ta_ptr = &(*ta_ptr)->next)
                ;
        if (sscanf(inLine->value, "%*s%s%s%s%s", allow, select_oc, button_label, dn_extension) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    do {
        *ta_ptr = (pTABLE_DISPLAY) ch_calloc(1, sizeof(TABLE_DISPLAY));
        (*ta_ptr)->allow = !strcasecmp(allow, "ALLOW") ? 1 : 0;
        (*ta_ptr)->select_oc = str_tolower( strdup( select_oc ));
        (*ta_ptr)->button_label = strdup( button_label );
        (*ta_ptr)->dn_extension = str_tolower( strdup( dn_extension ));
        ta_ptr = &(*ta_ptr)->next;
        if(!do_readf(inLine, NULL))
                        return (OK);
        if (sscanf(inLine->value, "%s%s%s%s", allow, select_oc, button_label, dn_extension) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
    return (DONE);
}
/* end of function: table_disp */

PRIVATE int modify(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char tmp[BUFSIZ];
    pMODIF *m_ptr;

    sprintf (tmp, "|");
    for(m_ptr = &glob->modify; *m_ptr; m_ptr = &(*m_ptr)->next)
                ;
    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*[^\"]\"%[^\"]", tmp+1) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s", tmp+1) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    *m_ptr = (pMODIF) ch_calloc(1, sizeof(MODIF));
    strcat (tmp, "|");
    (*m_ptr)->ocs = str_tolower (tr1 (strdup(tmp), ' ', '|'));

    if(!do_readf(inLine, NULL)) return (NOTOK);
    return (parse(inLine,disp->subTable, glob, ++level));
}
/* end of function: modify */

PRIVATE int ind_attrs(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char tmp[BUFSIZ];
    pIND_ATTRS *i_ptr;

    for(i_ptr = &glob->ind_attrs; *i_ptr; i_ptr = &(*i_ptr)->next)
                ;
    if (sscanf(inLine->value, "%*s%s", tmp) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    *i_ptr = (pIND_ATTRS) ch_calloc(1, sizeof(IND_ATTRS));
    (*i_ptr)->ref_attr = str_tolower(strdup(tmp));

    if(!do_readf(inLine, NULL)) return (NOTOK);
    return (parse(inLine,disp->subTable, glob, ++level));
}
/* end of function: ind_attrs */

PRIVATE int cache_expire(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_int_param(inLine, &glob->cache_expire, glob));
}
/* end of function: cache_expire */

PRIVATE int maxcount(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_int_param(inLine, &glob->maxcount, glob));
}
/* end of function: maxcount */

PRIVATE int language(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];
int slots = 2, i = 0;

    glob->language = (char **) ch_calloc(slots+1, sizeof(char **));
    if (sscanf(inLine->value, "%*s%s", tmp) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    do {
        if(i == slots){
            slots *= 2;
            glob->language =  (char **) ch_realloc((char *)glob->language, (slots+1)*sizeof(char **));
        }
        glob->language[i++] = strdup(tmp);
        if(!do_readf(inLine, NULL))
                        return (OK);
        if (sscanf(inLine->value, "%s", tmp) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
    return (DONE);
}
/* end of function: language */

PRIVATE int strict_basedn(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->strict_basedn = 1;
    return (OK);
}
/* end of function: strict_basedn */

PRIVATE int pull_down_menus(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->pull_down_menus = 1;
    return (OK);
}
/* end of function: pull_down_menus */

PRIVATE int no_proxy(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->no_proxy = 1;
    return (OK);
}
/* end of function: no_proxy */

PRIVATE int disp_sea_rdn(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->disp_sea_rdn = 1;
    return (OK);
}
/* end of function: disp_sea_rdn */

PRIVATE int prefer_ref_uris(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    glob->prefer_ref_uris = 1;
    return (OK);
}
/* end of function: prefer_ref_uris */

PRIVATE int strip_pin(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{

    return(get_str_param(inLine, &glob->strip_pin, glob, 1));
}
/* end of function: strip_pin */

PRIVATE int legal(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char tmp[BUFSIZ];

    sscanf(inLine->value, "%*s%s", tmp);
    glob->legal = 1;
    glob->legal_top = tmp && !strcasecmp(tmp, "ON-TOP");
    return (OK);
}
/* end of function: legal */

PRIVATE int no_modify(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->no_modify, glob, 1));
}
/* end of function: no_modify */

PRIVATE int no_show_rdn(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->no_show_rdn, glob, 1));
}
/* end of function: no_show_rdn */

PRIVATE int sort(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char object_class[BUFSIZ];
    char label[BUFSIZ];
    char priority[BUFSIZ];
    char display_class[BUFSIZ];
    char sort_attr[BUFSIZ];
    pSORT_LINE *s_ptr;

    s_ptr = &glob->sort;
    strcpy(sort_attr, "sn");
    strcpy( display_class, "default" );

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%*[^\"]\"%[^\"]\"%s%s%s", object_class, label, priority, display_class, sort_attr) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    } else
        if (sscanf(inLine->value, "%*s%s%s%s%s%s", object_class, label, priority, display_class, sort_attr) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    do {
        char tmpBuf[BUFSIZ];

        *s_ptr = (pSORT_LINE) ch_calloc(1, sizeof(SORT_LINE));
        sprintf (tmpBuf, "|%s|", object_class);
        (*s_ptr)->object_class = str_tolower (strdup(tmpBuf));
        (*s_ptr)->label = strdup(label);
        (*s_ptr)->priority = atoi(priority);
        (*s_ptr)->display_class = str_tolower( strdup( display_class ));
        (*s_ptr)->sort_attr = strdup( str_tolower( sort_attr ));
        s_ptr = &(*s_ptr)->next;

        if(!charray_inlist(glob->sort_attribs, sort_attr))
            charray_add(&glob->sort_attribs, sort_attr );

        if(!do_readf(inLine, NULL))
            return (OK);

        strcpy(sort_attr, "sn");
        strcpy( display_class, "default" );

        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%*[^\"]\"%[^\"]\"%s%s%s", object_class, label, priority, display_class, sort_attr) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s%s%s", object_class, label, priority, display_class, sort_attr) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');

    return (DONE);
}
/* end of function: sort */

PRIVATE int form_button(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char read_menu[BUFSIZ];
    char object_class[BUFSIZ];
    char method[BUFSIZ];
    char script_url[BUFSIZ];
    char text[BUFSIZ];
    char dn_name[BUFSIZ];
    char form_name[BUFSIZ];
    char button_label[BUFSIZ];
    pFORM_BUTTON *f_ptr;

    f_ptr = &glob->form_button;
/*    for(f_ptr = &glob->form_button; (*f_ptr)->next; f_ptr = &(*f_ptr)->next)
            ;
*/

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%s%s%s%*[^\"]\"%[^\"]\"%s%s%s", read_menu, object_class, method, script_url, text, dn_name, form_name, button_label) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    } else
        if (sscanf(inLine->value, "%*s%s%s%s%s%s%s%s%s", read_menu, object_class, method, script_url, text, dn_name, form_name, button_label) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    do {

        *f_ptr = (pFORM_BUTTON) ch_calloc(1, sizeof(FORM_BUTTON));
        (*f_ptr)->read_menu = strcasecmp(read_menu, "READ") ? 0 : 1;
        (*f_ptr)->object_class = strdup(object_class);
        (*f_ptr)->method = strdup(method);
        (*f_ptr)->script_url = strdup(script_url);
        (*f_ptr)->text = strdup(text);
        (*f_ptr)->dn_name = strdup(dn_name);
        (*f_ptr)->form_name = strdup(form_name);
        (*f_ptr)->button_label = strdup(button_label);
        f_ptr = &(*f_ptr)->next;

        if(!do_readf(inLine, NULL))
            return (OK);

        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%s%s%s%*[^\"]\"%[^\"]\"%s%s%s", read_menu, object_class, method, script_url, text, dn_name, form_name, button_label) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s%s%s%s%s%s", read_menu, object_class, method, script_url, text, dn_name, form_name, button_label) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');

    return (DONE);
}
/* end of function: form_button */

PRIVATE int firstPage(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char attribute[BUFSIZ];
char label[BUFSIZ];
char type[BUFSIZ];
pDISPLAY_LINE *dis_ptr;
pDISPLAY d_ptr;

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%*[^\"]\"%[^\"]\"%s", attribute, label, type) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%s%s", attribute, label, type) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    for(d_ptr = glob->display; d_ptr->next; d_ptr = d_ptr->next)
        ;
    dis_ptr = &d_ptr->first_page;
    do {
        *dis_ptr = (pDISPLAY_LINE) ch_calloc(1, sizeof(DISPLAY_LINE));
        (*dis_ptr)->attribute = str_tolower( strdup( attribute ));
        (*dis_ptr)->label = strdup(label);
        (*dis_ptr)->type = strdup( str_toupper( type ));
        (*dis_ptr)->ty = cnvt_str2int (type, disp_types, "DEFAULT");
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%*[^\"]\"%[^\"]\"%s", attribute, label, type) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s", attribute, label, type) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        dis_ptr = &(*dis_ptr)->next;

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');

    return (parse(inLine,disp->subTable, glob, ++level));
}
/* end of function: firstPage */

PRIVATE int secondPage(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char attribute[BUFSIZ];
char label[BUFSIZ];
char type[BUFSIZ];
pDISPLAY_LINE *dis_ptr;
pDISPLAY d_ptr;

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%*[^\"]\"%[^\"]\"%s", attribute, label, type) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%s%s", attribute, label, type) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    for(d_ptr = glob->display; d_ptr->next; d_ptr = d_ptr->next)
        ;
    dis_ptr = &d_ptr->second_page;
    do {
        *dis_ptr = (pDISPLAY_LINE) ch_calloc(1, sizeof(DISPLAY_LINE));
        (*dis_ptr)->attribute = str_tolower( strdup( attribute ));
        (*dis_ptr)->label = strdup(label);
        (*dis_ptr)->type = strdup( str_toupper( type ));
        (*dis_ptr)->ty = cnvt_str2int (type, disp_types, "DEFAULT");
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%*[^\"]\"%[^\"]\"%s", attribute, label, type) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s", attribute, label, type) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        dis_ptr = &(*dis_ptr)->next;

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
/*puts("leaving secondpage!");
*/

    return (DONE);
}
/* end of function: secondPage */

PRIVATE int modattr(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char attribute[BUFSIZ];
char label[BUFSIZ];
char count[BUFSIZ];
pMODIFY_LINE *mod_ptr;
pMODIF m_ptr;

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%*[^\"]\"%[^\"]\"%s", attribute, label, count) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%s%s", attribute, label, count) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

        for(m_ptr = glob->modify; m_ptr->next; m_ptr = m_ptr->next)
                ;
    mod_ptr = &m_ptr->modattr;
    do {
        *mod_ptr = (pMODIFY_LINE) ch_calloc(1, sizeof(MODIFY_LINE));
        (*mod_ptr)->attribute = str_tolower( strdup( attribute ));
        (*mod_ptr)->label = strdup(label);
        (*mod_ptr)->count = atoi(count);
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%*[^\"]\"%[^\"]\"%s", attribute, label, count) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s", attribute, label, count) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        mod_ptr = &(*mod_ptr)->next;

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');
/*puts("leaving secondpage!");
*/

    return (DONE);
}
/* end of function: modattr */

PRIVATE int ind_attribute(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
char key[BUFSIZ];
char replace[BUFSIZ];
char attribute[BUFSIZ];
char host[BUFSIZ];
char port[BUFSIZ];
char base[BUFSIZ];
pIND_ATTRS i_ptr;
IND_ATTR_ARR **idx;
int i;

    if(strchr(inLine->value, '"')) {
        if (sscanf(inLine->value, "%*s%s%s%s%s%s%*[^\"]\"%[^\"]\"", key,
                              replace, attribute, host, port, base) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
    } else
        if (sscanf(inLine->value, "%*s%s%s%s%s%s%s", key, replace, attribute,
                                   host, port, base) < 1)
            fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    for(i_ptr = glob->ind_attrs; i_ptr->next; i_ptr = i_ptr->next)
        ;
    
    idx = &i_ptr->ia_arr;

    *idx = (IND_ATTR_ARR *) ch_malloc( 100 * sizeof(IND_ATTR_ARR) );
    i = 0;

    do {
        (*idx)[i].key = strdup(key);
        (*idx)[i].replace = !strcasecmp(replace, "function") ? 2 :
                            !strcasecmp(replace, "replace") ? 1 : 0;
        (*idx)[i].attr = strdup(attribute);
        (*idx)[i].host = strdup(host);
        (*idx)[i].port = atoi(port);
        (*idx)[i].base = strdup(base);
        (*idx)[++i].key = NULL;
        
        if(!do_readf(inLine, NULL))
                        return (OK);
        if(strchr(inLine->value, '"')) {
            if (sscanf(inLine->value, "%s%s%s%s%s%*[^\"]\"%[^\"]\"", key, replace, attribute, host, port, base) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);
        } else
            if (sscanf(inLine->value, "%s%s%s%s%s%s", key, replace, attribute, host, port, base) < 1)
                fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n", glob->acfilename, inLine->count, inLine->value);

    } while(inLine->value[0] == ' ' || inLine->value[0] == '\t');

    return (DONE);
}
/* end of function: ind_attribute */


PUBLIC void langinit(glob)
GLOB_STRUCT *glob;
{
    FILE *fp;
    char inLine[BUFSIZ], lCountS[BUFSIZ], phrase[BUFSIZ], file[BUFSIZ];

    sprintf( file, "%s.lang.%s", glob->argv0, glob->lang );
    if(!(fp = fopen(file, "r"))) {
        fprintf(stderr, "\n\nATTENTION!!!\n\nCould not open file %s !\n", file);
        exit(0);
    }
    while(fgets(inLine, BUFSIZ-1, fp)) {

        /* Comment-sign is accepted in the first column only */
        if(*inLine == '#')
            *inLine = '\0';
        if(*inLine == '\t') {
            strcat(strcat(glob->la[atoi(lCountS)], " "), trim(inLine, " \t\n"));
            continue;
        }
        if(!*(trim(inLine, " \t\n"))) continue;
        sscanf(trim(inLine, " \t\n"), "%s %[^\n]", lCountS, phrase);
        if(*glob->la[atoi(lCountS)])
            fprintf(stderr, "\nWarning: glob->la[%s] existed already with value <%s> and was overwritten with value <%s> !\n\n", lCountS, glob->la[atoi(lCountS)], phrase );
        strcpy(glob->la[atoi(lCountS)], phrase);
    }

}
/* end of function: langinit */

PUBLIC void langoutput(fp, glob, html_flag)
FILE *fp;
GLOB_STRUCT *glob;
int html_flag;
{
    int i;

    fprintf(fp, "%s\n\n\nLanguage Settings\n\n%s",html_flag ? "<H2>" : "", html_flag ? "</H2>" : "\n");
    for(i=0 ; i<LANG_ARR_SIZE; i++)
        if(*glob->la[i]) fprintf(fp, "%s%d%s\t%s%s", html_flag ? "<H2>" : "", i, html_flag ? "</H2>" : "", glob->la[i], html_flag ? "<br>" : "\n");
}
/* end of function: langoutput */

PUBLIC void get_lang(argc, argv, lang)
int argc;
char **argv;
char *lang;
{
    int    i;

    for(i=1;i<argc;i++)
        if (strstr(argv[i] , "-L")){
            strcpy(lang, argv[i]+2);
        }
    if(!*lang){
        usage(argv[0]);
        exit(0);
    }
}
/* end of function: get_lang */

PRIVATE int header(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->header, glob, 0));
}
/* end of function: header */

PRIVATE int footer(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->footer, glob, 0));
}
/* end of function: footer */

PRIVATE int allow_msg(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    return(get_str_param(inLine, &glob->allow_msg, glob, 0));
}
/* end of function: allow_msg */

PRIVATE int ip_refuse(inLine, disp, glob, level)
FILELINE *inLine;
PARSE_ENTRY *disp;
GLOB_STRUCT *glob;
int level;
{
    char dat_file[BUFSIZ];
    char rereadcycle[BUFSIZ];

    if (sscanf(inLine->value, "%*s%s%s", dat_file, rereadcycle) < 1)
        fprintf(stderr, "\nWarning: Error in init-file %s, line %d:\n%s\n",
                glob->acfilename, inLine->count, inLine->value);

    glob->ip_refuse  = (IP_REFUSE *) ch_calloc(1, sizeof(IP_REFUSE));
    glob->ip_refuse->dat_file = strdup( dat_file );
    glob->ip_refuse->rereadcycle = atoi(rereadcycle);

    return (OK);
}  /*  ip_refuse  */

PUBLIC void file_test(filename, etcdir)
char **filename;
char *etcdir;
{
    FILE *fp;
    char newfname[BUFSIZ];

    if(*filename){
        if(!(fp = fopen(*filename, "r"))) {
            sprintf(newfname, "%s%s", etcdir, *filename);
            if(!(fp = fopen(newfname, "r"))) {
                sprintf(newfname, "%s.%s", newfname, globP->lang);
                fp = fopen(newfname, "r");
            }
        }
        if(fp) {
            free(*filename);
            *filename = strdup(newfname);
            fclose(fp);
        } else {
            fprintf(stderr, "\n\nCould not open file %s !\n\n",
                            *filename);
        }
    }
}
/* end of function: file_test */

PRIVATE void f_test(glob)
GLOB_STRUCT *glob;
{
    pSEARCH_ONLY_LINE so_ptr;

    file_test(&glob->helpfile, glob->etcdir);
    file_test(&glob->filterfile, glob->etcdir);
    file_test(&glob->friendlyfile, glob->etcdir);
    file_test(&glob->header, glob->etcdir);
    file_test(&glob->footer, glob->etcdir);
    file_test(&glob->allow_msg, glob->etcdir);
    if(glob->basedn) {
        file_test(&glob->basedn->head, glob->etcdir);
        file_test(&glob->basedn->foot, glob->etcdir);
    }
    for(so_ptr = glob->search_only; so_ptr; so_ptr = so_ptr->next) {
        file_test(&so_ptr->head, glob->etcdir);
        file_test(&so_ptr->foot, glob->etcdir);
    }
}
/* end of function: f_test */



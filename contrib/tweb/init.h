/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* init.h.....                                                              *
*                                                                          *
* Function:..File for TWEB-SOFTWARE                                        *
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
*            May 14 1999                ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: init.h,v 1.6 1999/09/10 15:01:17 zrnsk01 Exp $
 *
 */

#ifndef _INIT_
#define _INIT_

#include <getopt.h>
#include "strng_exp.h"
#include "init_exp.h"
#include "charray_exp.h"
#include "ch_malloc_exp.h"
#include "support_exp.h"

#ifdef TUE_TEL
#  include "tueTel_exp.h"
#endif

#ifdef AMBIXGW
#  include "ambix_exp.h"
#endif


/* Usage-Text */
#define USAGE "\nUSAGE: %s -Lx[yz..] [-p webport] [-x ldaphost]\
         \n\t\t[-P ldapport] [-b basedn] [-f filterfile] [-l logger] [-d]\n\
    \n\
    A short description of TWEB WWW2X.500-Gateway: \n\n\
    (does not compensate reading the README files\n\
    and the correct configuration)\n\
    \n\
    Options:\n\n\
    -L:\ttells TWEB the numbers of the languages that have to be started,\n\
    \twherewith are also created the language-buttons\n\
    \tExample: tweb -L01 starts TWEB in german und english\n\
    -p:\tnames the port on which the gateway is to be reached\n\
    -x:\tnames the LDAP-Hosts\n\
    -P:\tnames the port of the LDAP-Server\n\
    -b:\tnames the DN where the gateway shall start by default\n\
    -f:\tnames the ldapfilter-file\n\
    -l:\tswitches on logging for example LOCAL3\n\
    -d:\tswitches on debugging (no sub-processes!)\n\
    \n"


/* Funktions in the init-module */
PRIVATE int webdn();
PRIVATE int webpw();
PRIVATE int webdn2();
PRIVATE int webpw2();
PRIVATE int webport();
PRIVATE int timeout();
PRIVATE int ldapd();
PRIVATE int ldapportf();
PRIVATE int hostname();
PRIVATE int header();
PRIVATE int footer();
PRIVATE int index_url();
PRIVATE int allow_msg();
PRIVATE int helpfilef();
PRIVATE int filterfilef();
PRIVATE int etcdir();
PRIVATE int friendlyfilef();
PRIVATE int grant();
PRIVATE int refuse();
PRIVATE int allow_string();
PRIVATE int allow_proxy();
PRIVATE int subtree_search();
PRIVATE int deny_string();
PRIVATE int show_defoc();
PRIVATE int display();
PRIVATE int basednf();
PRIVATE int search_only();
PRIVATE int gw_switch();
PRIVATE int modify();
PRIVATE int ind_attrs();
PRIVATE int ind_attribute();
PRIVATE int maxcount();
PRIVATE int cache_expire();
PRIVATE int max_person();
PRIVATE int caching_terms();
PRIVATE int comrefuse();
PRIVATE int language();
PRIVATE void f_test();
PRIVATE void main_loop();
PRIVATE int strip_pin();
PRIVATE int prefer_ref_uris();
PRIVATE int pull_down_menus();
PRIVATE int no_proxy();
PRIVATE int disp_sea_rdn();
PRIVATE int strict_basedn();
PRIVATE int dynamic_gw();
PRIVATE int legal();
PRIVATE int no_show_rdn();
PRIVATE int no_modify();
PRIVATE int sort();
PRIVATE int firstPage();
PRIVATE int secondPage();
PRIVATE int modattr();
PRIVATE void usage();
PRIVATE int parse();
PRIVATE int parse2();
PRIVATE int table_disp();
PRIVATE int form_button();
PRIVATE int ip_refuse();


/* Sub-tables to analyse the DISPLAY-Keys */
static PARSE_ENTRY first_table[] = {
    {"SECOND-PAGE",        secondPage,        NULL},
    { NULL, NULL, NULL }
};

static PARSE_ENTRY display_table[] = {
    {"FIRST-PAGE",         firstPage,        first_table},
    { NULL, NULL, NULL }
};


/* Sub-tables to analyse the MODIFY-Keys */
static PARSE_ENTRY modify_table[] = {
    {"MODATTR",            modattr,          NULL},
    { NULL, NULL, NULL }
};

/* Sub-tables to analyse the IND_ATTRS-Keys */
static PARSE_ENTRY ind_attrs_table[] = {
    {"IND_ATTRS",            ind_attribute,          NULL},
    { NULL, NULL, NULL }
};


/* The main-table for key-word-parsing */
static PARSE_ENTRY parse_table[] = {
    {"WEBDN",              webdn,            NULL},
    {"WEBPW",              webpw,            NULL},
    {"WEBDN2",             webdn2,           NULL},
    {"WEBPW2",             webpw2,           NULL},
    {"WEBPORT",            webport,          NULL},
    {"TIMEOUT",            timeout,          NULL},
    {"TWEBHOST",           hostname,         NULL},
    {"LDAPD",              ldapd,            NULL},
    {"LDAPPORT",           ldapportf,        NULL},
    {"HEADER",             header,           NULL},
    {"FOOTER",             footer,           NULL},
    {"INDEX-URL",          index_url,        NULL},
    {"ALLOW-MSG",          allow_msg,        NULL},
    {"HELPFILE",           helpfilef,        NULL},
    {"FILTERFILE",         filterfilef,      NULL},
    {"ETCDIR",             etcdir,           NULL},
    {"FRIENDLYFILE",       friendlyfilef,    NULL},
    {"GRANT",              grant,            NULL},
    {"REFUSE",             refuse,           NULL},
    {"ALLOW-STRING",       allow_string,     NULL},
    {"ALLOW-PROXY",        allow_proxy,      NULL},
    {"SUBTREE-SEARCH",     subtree_search,   NULL},
    {"DENY-STRING",        deny_string,      NULL},
    {"SHOW-DEFAULT-OC",    show_defoc,       NULL},
    {"DISPLAY-OBJECT" ,    display,          display_table},
    {"BASEDN",             basednf,          NULL},
    {"SEARCH-ONLY",        search_only,      NULL},
    {"GW-SWITCH",          gw_switch,        NULL},
    {"MODIFY",             modify,           modify_table},
    {"INDIRECT-ATTRS",     ind_attrs,        ind_attrs_table},
    {"MAXCOUNT",           maxcount,         NULL},
    {"CACHE-EXPIRE-DEFAULT", cache_expire,   NULL},
    {"MAX-PERSON",         max_person,       NULL},
    {"CACHING-TERMS",      caching_terms,    NULL},
    {"COMREFUSE",          comrefuse,        NULL},
    {"LANGUAGE",           language,         NULL},
    {"STRIP-PIN",          strip_pin,        NULL},
    {"PREFER-REF-URIS",    prefer_ref_uris,  NULL},
    {"PULL-DOWN-MENUS",    pull_down_menus,  NULL},
    {"NO-PROXY",           no_proxy,         NULL},
    {"DISP-SEA-RDN",       disp_sea_rdn,     NULL},
    {"STRICT-BASEDN",      strict_basedn,    NULL},
    {"DYNAMIC-GW",         dynamic_gw,       NULL},
    {"LEGAL",              legal,            NULL},
    {"NO-SHOW-RDN",        no_show_rdn,      NULL},
    {"NO-MODIFY",          no_modify,        NULL},
    {"SORT",               sort,             NULL},
    {"TABLES",             table_disp,       NULL},
    {"FORM-BUTTON",        form_button,      NULL},

#ifdef AMBIXGW
    {"SELBSTEINTRAG",      selbsteintrag,    NULL},
#endif

#ifdef TUE_TEL
    {"DIT-CONFIG",         dit_config,       NULL},
    {"PHONEWORLD",         phoneworld,       NULL},
    {"TON-URLS",           ton_urls,         NULL},
#endif
    {"IP-REFUSE",          ip_refuse,        NULL},

    { NULL, NULL, NULL }
};


/* tables to compute DISPLAY-types to integer */
STRDISP  disp_types[] = {

    { "DEFAULT",         3, 0 },
    { "MAILTO",          4, 6 },
    { "MULTILINE",       5, 1 },
    { "JPEG",            4, 9 },
    { "JPEG2GIF",        8, 10 },
    { "BMP",             3, 8 },
    { "HREF",            4, 2 },
    { "URL",             3, 5 },
    { "FINGER",          6, 3 },
    { "DATE",            4, 4 },
    { "MOVETO",          4, 7 },
    { "BOOLEAN",         9, 11 },
    { "URI",             3, 12 },
    { "PGPKEY",          6, 13 },
    { "INDEXURL",        8, 14 },
    { "DYNAMICDN",       9, 15 },
    { "REFERRAL",        8, 20 },
    { "PRE",             3, 21 },
    { "HEADER",          6, 22 },

#ifdef TUE_TEL
    { "PHONREFSHORT",   12, 16 },
    { "PHONREFLONG",    11, 17 },
    { "TFUNCPERS",       9, 18 },
    { "FAXTABLE",        8, 19 },
#endif

    { NULL, 0, 0 }

};

/* tables to compute syslog-options to integer */
static STRDISP  syslog_types[] = {

    { "LOCAL0",         6, LOG_LOCAL0 },
    { "LOCAL1",         6, LOG_LOCAL1 },
    { "LOCAL2",         6, LOG_LOCAL2 },
    { "LOCAL3",         6, LOG_LOCAL3 },
    { "LOCAL4",         6, LOG_LOCAL4 },
    { "LOCAL5",         6, LOG_LOCAL5 },
    { "LOCAL6",         6, LOG_LOCAL6 },
    { "LOCAL7",         6, LOG_LOCAL7 },
    { NULL, 0, 0 }

};


/* Defaults */
#define  DEFAULT_TIMEOUT   120
#define  DEFAULT_MAXCOUNT  200
#define  MAX_EXPIRE        604800


/*  Variable for the Anti-Hack-Code */
extern COMREFUSE  *comRefuseP;

struct timeval timestore[5];    /* Time assigned to events:
                                    0 -> after accept, 1-> after dns,
                                    2 -> after check4access,
                                    3 -> before list_output/print_attr */

int items_displayed = 0;         /* number of items showed on
                                    do_menu/do_search*/

#endif /* _INIT_ */


/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* init_exp.h.                                                              *
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
*            May 11 1999                ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/
/*
 * $Id: init_exp.h,v 1.6 1999/09/10 15:01:17 zrnsk01 Exp $
 *
 */


#ifndef _INIT_EXP_
#define _INIT_EXP_

#ifdef TUE_TEL
#  include  "tueTel_exp.h"
#endif

#include "regular_exp.h"

PUBLIC int  get_str_param(/* FILELINE *inLine, char **str,
                             GLOB_STRUCT *glob, int lower */);

PUBLIC void getopts ();
PUBLIC void check ();
PUBLIC void init();
PUBLIC void output();
PUBLIC void langinit();
PUBLIC void langoutput();
PUBLIC void get_lang();
PUBLIC void file_test();
PUBLIC int  do_readf();
PUBLIC void get_index_url_rules();
PUBLIC void re_read_index_url_rules();

extern  STRDISP  disp_types[];


/* A pointer to an integer-function */
typedef int (*IFP)();


/* One line in the config-file, with line-counter */
typedef struct _fileline {
    char value[BUFSIZ];
    int count;
} FILELINE;


/* Table-structure to parse the key-words in the config- und rc-files */
typedef struct _parse_keys {
    char *keyWord;
    IFP   keyFunc;
    struct _parse_keys *subTable;
} PARSE_ENTRY;


/* Maximum number of sub-lists in order to display result-lists */
#define MAX_OCS 128

/* List of attributes which will be displayed (on 1./2. page) */
typedef struct _display_line {
    char *attribute;              /* the X.500-Attribute */
    char *label;                  /* the Label of the Web-Page */
    char *type;                   /* the Format-Type as String (C-Option) */
    int ty;                       /* the Format-Type as Int (print-Funkt.) */
    struct _display_line *next;   /* the next Attribute */
} DISPLAY_LINE, *pDISPLAY_LINE;


/* List of Object-Classes which shall be displayed */
typedef struct _display {
    char *ocs;                    /* the X.500-Object-Class(es) */
    DISPLAY_LINE *first_page;     /* Attribute on the first page */
    DISPLAY_LINE *second_page;    /* Attribute on the second page */
    struct _display *next;        /* the next Objekt-Class(es) */
} DISPLAY, *pDISPLAY;


/* List of attributes which may be modified */
typedef struct _modify_line {
    char *attribute;              /* the X.500-attribute */
    char *label;                  /* the Label in the modification-formulare */
    int   count;                  /* the maximmum number of attribute-values */
    struct _modify_line *next;    /* the next attribute */
} MODIFY_LINE, *pMODIFY_LINE;

/* List of Object-Class(es) which may be modified */
typedef struct _modify {
    char *ocs;                    /* the X.500-Object-Class(es) */
    MODIFY_LINE *modattr;         /* the modifyable attributes */
    struct _modify *next;         /* the next Object-Class(es) */
} MODIF, *pMODIF;

/*attributes which are read from another entry */
typedef struct _ind_attr_arr {
    char *key;                    /* pers for person etc. */
    int replace;                  /* 2 -> function, 1 -> replace, 0 -> append */
    char *attr;                   /* functionname / referenced attribute */
    char *host;                   /* on which host to look */
    int port;                     /* on which port to look */
    char *base;                   /* where to look for ref-entry */
    LDAPMessage **e;              /* Pointer to the result */
    LDAP *ld;                     /* Pointer to the matching LDAP-Struct */
} IND_ATTR_ARR;

typedef struct _ind_attrs {
    char *ref_attr;               /* name of the reference-attribute */
    IND_ATTR_ARR *valid_nodes;    /* valid nodes array (only in 1st element) */
    IND_ATTR_ARR *ia_arr;         /* supported keys, attrs and bases */
    struct _ind_attrs *next;      /* the next ind_attr */
} IND_ATTRS, *pIND_ATTRS;


/* Support-structure to sort the result-lists */
typedef struct _dncompare {
    char *string;                 /* Sort-String */
    char *href;                   /* Hyper-Link for the sorted entry */
    char *raw;                    /* Raw data:                                                                         -> <name>[<attr>=<value>&..%..$.. */
} DNLIST, *pDNLIST;


/* Structure to sort the result-lists object-class/attribute-related */
typedef struct _sort_line {
    char *object_class;           /* Object-class by which is sorted */
    char *label;                  /* Label to display sub-lists */
    int   priority;               /* Sequence for list-output */
    char *display_class;          /* dedicated display-class */
    DISPLAY *display_class_ptr;   /* Pointer therefor */
    char *sort_attr;              /* Attribut by which sorting is done */
    pDNLIST *dnList;              /* Entries in the sub-list */
    int  dnLast;                  /* Amount of entries in the sub-list */
    int restricted;               /* 1 -> sub-list was restricted : 0 -> not*/
    struct _sort_line *next;      /* the next Object-Class */
} SORT_LINE, *pSORT_LINE;

/* Structure to handle caching */

typedef struct _caching_terms_line {
    int time;                     /* time to cache */
    char *access_type;            /* type of access */
    int rdn_oc;                   /* 1 -> rdn, 0 -> oc -lookup */
    char *pattern;                /* mach-pattern: oc/rdn */
    struct _caching_terms_line *next; /* the next line */
} CACHING_TERMS_LINE, *pCACHING_TERMS_LINE;


/* DN of the TWEB-Homepage, including header and footer thereof */
typedef struct _basedn_line {
    char *dn;
    char **dnarray;
    char *head;
    char *foot;
} BASEDN_LINE;

/* List of rules for table-button and table display */
typedef struct _table_display {
    int allow;            /* 1 -> tables only if allowed, 0 -> in any case */
    char *select_oc;      /* table-button only if
                             objectclass contains select_oc */
    char *button_label;   /* label for table-request-button */
    char *dn_extension;   /* extension behind button Xdn?MENU */
    struct _table_display *next;
} TABLE_DISPLAY, *pTABLE_DISPLAY;

/* List of organisational units where only searching is permitted,
   including header and footer thereof */
typedef struct _search_only_line {
    char *dn;
    char *head;
    char *foot;
    struct _search_only_line *next;
} SEARCH_ONLY_LINE, *pSEARCH_ONLY_LINE;

/* Anti-Hack Structure */
typedef struct _comrefuse {
    int      tmin;
    int      tdiff;
    int      maxAccept;
    int      suspendCycle;
    time_t   statCycle;
    char    *statFile;
} COMREFUSE;
    

/* static list of Gateway-Switches */
typedef struct _gw_switch_line {
    char *dn;                     /* the DN of the organization(al unit) */
    char *url;                    /* the URL of the gateway to be called */
    struct _gw_switch_line *next; /* the next Gateway-Switch */
} GW_SWITCH_LINE, *pGW_SWITCH_LINE;

/* the head of the Gateway-Switch-list */
typedef struct _gw_switch {
    int dynamic;                  /* is dynamic switching allowed */
    char *lagws;                  /* language dependant recognition of
                                     GW-Switch-entries in X.500
                                     (language independant recognition is
                                      implemented by macro) */
    GW_SWITCH_LINE *list;         /* the static list of switches */
} GW_SWITCH, *pGW_SWITCH;

/* static list of already available ldap-connections */
typedef struct _ld_list {
    LDAP *ld;                     /* pointer to the ldap-structure */
    char *host;                   /* The corresponding host */
    int port;                     /* The corresponding port */
    struct _ld_list *next;        /* the next */
} LD_LIST, *pLD_LIST;

typedef struct _index_url_rule {
    char *rule;                   /* Atribute providing data */
    char *dit_dn;               /* DN supporting config */
} INDEX_URL_RULE;

typedef struct _index_url {
    char *dat_file;             /* File providing data */
#define INDEX_RULE_SIZE     20
    INDEX_URL_RULE rarr[INDEX_RULE_SIZE];  /* array with rules */
    int rereadcycle;            /* frequency to reread */
} INDEX_URL;

/* Structure to hold config of buttons leading to form-scripts */
typedef struct _form_button {
    int   read_menu;              /* 1-> button in do_read; 0-> in do_menu */
    char *object_class;           /* display the button on presence of this
                                     object-class*/
    char *method;                 /* cgi method: GET ..  */
    char *script_url;             /* URL of CGI-Script */
    char *text;                   /* text in front of button */
    char *dn_name;                /* name of dn in hidden form  */
    char *form_name;              /* name of form (submit-button) */
    char *button_label;           /* label of submit-button  */
    struct _form_button *next;    /* the next FORM_BUTTON definition */
} FORM_BUTTON, *pFORM_BUTTON;

typedef struct _ip_refuse {
    char *dat_file;             /* File providing data */
    char *refu_str;             /* String of refused clients */
#define REFU_BUFSIZ     256
#define REFU_STRDELIM   "&"

    int rereadcycle;            /* frequency to reread */
} IP_REFUSE;

/* the central structure of TWEB with the configuration of the gateway */
typedef struct _glob_struct {
    char *webdn;                 /* GW-DN in case of authorisded access */
    char *webpw;                 /* GW-PW in case of authorisded access */
    char *webdn2;                /* GW-DN in case of non-authorisded access */
    char *webpw2;                /* GW-PW in case of non-authorisded access */
    int  webport;                /* the Port the GW is listening on */
    int  timeout;                /* how long does the gateway wait for the DSA*/
    time_t stat_slice;           /* Time for the anti-Hack + Statistic */
    char *ldapd;                 /* the computer LDAPD is running on */
    int  ldapport;               /* the Port thereof */
    char *grant;                 /* ':'-separated list of domains with access */
    char *refuse;                /* ':'-separated list of domains
                                    without access */
    char *allow_string;          /* ':'-separated list of domains
                                    supported with authorised access */
    char *deny_string;           /* ':'-separated list of domains
                                    supported with restricted access */
    regexp *comp_grant;          /* compiled regular expressions for GRANT */
    regexp *comp_refuse;          /* compiled regular expressions for REFUSE */
    regexp *comp_allow;          /* compiled regular expressions for ALLOW_ST */
    regexp *comp_deny;           /* compiled regular expressions for DENY_ST. */
    char **allow_proxy;          /* ':'-separated list of proxy-servers
                                    supported with authorised access */
    char **subtree_search;       /* ':'-separated list of objectclasses
                                     where to make subtree_search instead of
                                     single_level_search */
    DISPLAY *display;            /* presentation of Objects */
	DISPLAY *default_display_type; /* pointer to the default display descript */
    BASEDN_LINE *basedn;         /* the entry-page of TWEB */
    SEARCH_ONLY_LINE *search_only; /* where only searching is supported */
    GW_SWITCH *gw_switch;        /* the Gateway-Switching */
    MODIF *modify;               /* what may be modified within TWEB */
    IND_ATTRS *ind_attrs;        /*attributes which are read from 
                                   another entry */
    int cache_expire;            /* caching-time for proxies in seconds */
    CACHING_TERMS_LINE *caching_terms; /* cache-control-rules */
    int maxcount;                /* maximum amount of result-lists */
    int max_person;              /* maximum amount of persons displayed */
    COMREFUSE *comrefuse;        /* Anti-Hack Structure */
    TABLE_DISPLAY *tables;       /* listings also as tables by button-request */
    INDEX_URL *index_url;        /* how to display search-results of index
                                    -> display-type INDEX-URL */
    FORM_BUTTON *form_button;    /* display buttons leading to forms */
    char *tables_marker;         /* flag for menu with tables += their config */
    char **language;             /* the language links on a html-page */
    char lang[2];                /* the number of the "own" language */
    char *olang;                 /* the other languages */
    char *no_show_rdn;           /* String with "unvisible" DN parts */
    char *no_modify;             /* Objectclasses without MODIFY-button */
    SORT_LINE *sort;             /* how shall the results be sorted */
    SORT_LINE *sorty[MAX_OCS];   /* Array with the sorted lists */
    char **sort_attribs;         /* Array with the sort-attributes */
    char *myname;                /* the programname */
    char *argv0;                 /* ARGV[0] */
    char *hostname;              /* the name of the computer TWEB 
                                    is running on*/
    int virtualport;             /* port if defined is set in every link
                                    instead of webport (may always
                                    lead requests over www4ward) */
    char *header;                /* the header for the standardpage */
    char *footer;                /* the footer for the standardpage */
    char *allow_msg;             /* file containing allow-message */
    char *helpfile;              /* the helpfile */
    char *filterfile;            /* the filterfile for LDAP-search */
    char *etcdir;                /* the directory containing the supportfiles */
    char *friendlyfile;          /* the file for "more friendly" DNs */
    char *acfilename;            /* the name of the actual config-file */
    time_t nowtime;              /* actual time in tics */
    time_t expiretime;           /* time for cache to expire in tics */
    char *nowtimestr;            /* actual timestring in GMT */
    char *strip_pin;             /* truncation of PINs at named sort_ocs */
    char *expiretimestr;         /* timestring for cache to expire in GMT */
    char *server_connection_msg; /* TCP Connection-message */
    char *user_agent_msg;        /* User-Agent message */
    char *menu_filter;           /* menu_filter */
#define LANG_ARR_SIZE 110
    char la[LANG_ARR_SIZE][BUFSIZ];  /* language-specific text-fragments */
    LD_LIST *ld_list;            /* List of open LDAP-Connections */
    char **raw_attrs;            /* Attributes to be shown with raw_access */
	size_t  svc_cnt;             /* A counter for the number of requests */

#ifdef TUE_TEL
    DIT_CONFIG *dit_config;      /* container for relations between DNs and
                                    responsible host:port */
    TON_URLS *ton_urls;          /* TONs in addition to DNs */
    char *phoneworld;            /* visibility of phonebook */
#endif
    IP_REFUSE *ip_refuse;        /* refuse certain hosts by ip-addr */

#ifdef AMBIXGW
    char *selbsteintrag[10];     /* some strings for AMBIX-selfentry */
#endif

    unsigned show_defoc     : 1, /* respect unknown OCs while sorting */
             strict         : 1, /* restriction of person-lists also in the
                                    authorised case */
             restricted     : 1, /* hard restriction of the extent of the list*/
             persRestricted : 1, /* restriction of person-lists (legal) */
             prefer_ref_uris : 1, /* take over labeledURIS from 
                                    referenced objects */
             is_proxy       : 1, /* did the request come from a proxy-server */
             pull_down_menus : 1, /* move upwards with pull-down-menus */
             no_proxy       : 1, /* no local proxy-servers */
             strict_basedn  : 1, /* no access outside BASEDN */
             no_browse      : 1, /* no person-lists while browsing */
             noauth         : 1, /* dynamic flag for question of authorisation*/
             caching        : 1, /* shall be cached by proxy-server */
             legal          : 1, /* display privacy-text */
             legal_top      : 1, /* display privacy-text on top */
             unknown_host   : 1, /* connection from unknown */
             allowed        : 1; /* access allowed for decide_access */
    unsigned raw_data       : 1, /* provide raw-data instead of html */
             ldap_referral_mode : 1, /* TWEB displayes foreign ldap-url */
             disp_sea_rdn   : 1; /* display only rdns as search-result */
} GLOB_STRUCT, *pGLOB_STRUCT;


/* the function the gateway is initialized with */
void init();

#endif /* _INIT_EXP_ */


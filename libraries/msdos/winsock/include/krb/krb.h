/*
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Include file for the Kerberos library.
 */

/* Only one time, please */
#ifndef KRB_DEFS
#define KRB_DEFS

#include <mit_copy.h>
#include <conf.h>

/* Need some defs from des.h     */
#include <des.h>

/* Text describing error codes */
#define         MAX_KRB_ERRORS  256
#ifndef WINDOWS
extern char *krb_err_txt[MAX_KRB_ERRORS];
#else
extern char FAR *krb_err_txt[MAX_KRB_ERRORS];
#endif


/* These are not defined for at least SunOS 3.3 and Ultrix 2.2 */
#if defined(ULTRIX022) || (defined(SunOS) && SunOS < 40)
#define FD_ZERO(p)  ((p)->fds_bits[0] = 0)
#define FD_SET(n, p)   ((p)->fds_bits[0] |= (1 << (n)))
#define FD_ISSET(n, p)   ((p)->fds_bits[0] & (1 << (n)))
#endif /* ULTRIX022 || SunOS */

/* General definitions */
#define         KSUCCESS        0
#define         KFAILURE        255

#ifdef NO_UIDGID_T
typedef unsigned short uid_t;
typedef unsigned short gid_t;
#endif /* NO_UIDGID_T */

/*
 * Kerberos specific definitions
 *
 * KRBLOG is the log file for the kerberos master server. KRB_CONF is
 * the configuration file where different host machines running master
 * and slave servers can be found. KRB_MASTER is the name of the
 * machine with the master database.  The admin_server runs on this
 * machine, and all changes to the db (as opposed to read-only
 * requests, which can go to slaves) must go to it. KRB_HOST is the
 * default machine * when looking for a kerberos slave server.  Other
 * possibilities are * in the KRB_CONF file. KRB_REALM is the name of
 * the realm.
 */

#ifdef notdef
this is server - only, does not belong here;
#define         KRBLOG          "/kerberos/kerberos.log"
are these used anyplace '?';
#define         VX_KRB_HSTFILE  "/etc/krbhst"
#define         PC_KRB_HSTFILE  "\\kerberos\\krbhst"
#endif
#ifdef IBMPC
#define         KRB_CONF        "%s\\kerb\\krb.con"
#define         KRB_RLM_TRANS   "%s\\KERB\\krbrealm.con"
#else
#define         KRB_CONF        "/etc/krb.conf"
#define         KRB_RLM_TRANS   "/etc/krb.realms"
#endif
#define         KRB_MASTER      "kerberos.mit.edu"
#define         KRB_REALM       "ATHENA.MIT.EDU"
#define         KRB_HOST         KRB_MASTER

/* The maximum sizes for aname, realm, sname, and instance +1 */
#define         ANAME_SZ        40
#define         REALM_SZ        40
#define         SNAME_SZ        40
#define         INST_SZ         40
/* include space for '.' and '@' */
#define         MAX_K_NAME_SZ   (ANAME_SZ + INST_SZ + REALM_SZ + 2)
#define         KKEY_SZ         100
#define         VERSION_SZ      1
#define         MSG_TYPE_SZ     1
#define         DATE_SZ         26      /* RTI date output */

#define         MAX_HSTNM       100

#ifndef DEFAULT_TKT_LIFE                /* allow compile-time override */
#define         DEFAULT_TKT_LIFE        96 /* default lifetime for krb_mk_req
                                              & co., 8 hrs */
#endif

/* Definition of text structure used to pass text around */
#define         MAX_KTXT_LEN    1250

struct ktext {
    int     length;             /* Length of the text */
    unsigned char dat[MAX_KTXT_LEN];    /* The data itself */
    unsigned long mbz;          /* zero to catch runaway strings */
};

typedef struct ktext far *KTEXT;
typedef struct ktext far *KTEXT_FP;
typedef struct ktext KTEXT_ST;


/* Definitions for send_to_kdc */
#define CLIENT_KRB_TIMEOUT      10       /* time between retries */ /* changed from 4, 8-14-94 pbh */
#define CLIENT_KRB_RETRY        5       /* retry this many times */
#define CLIENT_KRB_BUFLEN       512     /* max unfragmented packet */

/* Definitions for ticket file utilities */
#define R_TKT_FIL       0
#define W_TKT_FIL       1

/* Definitions for cl_get_tgt */
#ifdef PC
#define CL_GTGT_INIT_FILE               "\\kerberos\\k_in_tkts"
#else
#define CL_GTGT_INIT_FILE               "/etc/k_in_tkts"
#endif /* PC */

/* Parameters for rd_ap_req */
/* Maximum alloable clock skew in seconds */
#define         CLOCK_SKEW      5*60
/* Filename for readservkey */
#define         KEYFILE         "/etc/srvtab"

/* Structure definition for rd_ap_req */

struct auth_dat {
    unsigned char k_flags;      /* Flags from ticket */
    char    pname[ANAME_SZ];    /* Principal's name */
    char    pinst[INST_SZ];     /* His Instance */
    char    prealm[REALM_SZ];   /* His Realm */
    unsigned long checksum;     /* Data checksum (opt) */
    C_Block session;            /* Session Key */
    int     life;               /* Life of ticket */
    unsigned long time_sec;     /* Time ticket issued */
    unsigned long address;      /* Address in ticket */
    KTEXT_ST reply;             /* Auth reply (opt) */
};

typedef struct auth_dat AUTH_DAT;

/* Structure definition for credentials returned by get_cred */

struct credentials {
    char    service[ANAME_SZ];  /* Service name */
    char    instance[INST_SZ];  /* Instance */
    char    realm[REALM_SZ];    /* Auth domain */
    C_Block session;            /* Session key */
    int     lifetime;           /* Lifetime */
    int     kvno;               /* Key version number */
    KTEXT_ST ticket_st;         /* The ticket itself */
    long    issue_date;         /* The issue time */
    char    pname[ANAME_SZ];    /* Principal's name */
    char    pinst[INST_SZ];     /* Principal's instance */
};

typedef struct credentials CREDENTIALS;

/* Structure definition for rd_private_msg and rd_safe_msg */

struct msg_dat {
    unsigned char far *app_data;        /* pointer to appl data */
    unsigned long app_length;   /* length of appl data */
    unsigned long hash;         /* hash to lookup replay */
    int     swap;               /* swap bytes? */
    long    time_sec;           /* msg timestamp seconds */
    unsigned char time_5ms;     /* msg timestamp 5ms units */
};

typedef struct msg_dat MSG_DAT;


/* Location of ticket file for save_cred and get_cred */
#define TKT_FILE tkt_string()
#define TKT_ENV                 "KERBEROS_TICKETS"
typedef struct {
        unsigned buf_size;
        unsigned dummy;
        unsigned eof_ptr;
        int sema;               /* semaphore 0 - OK, -1 - lock write, +ve lock read */
} tkt_header;

tkt_header far *tkt_ptr(void);

#define KM_TKFILE 0
#define KM_KRBMEM 1

#define TKT_ROOT        "/tmp/tkt"  /* not used in OS/2 anyway */

/* Error codes returned from the KDC */
#define         KDC_OK          0       /* Request OK */
#define         KDC_NAME_EXP    1       /* Principal expired */
#define         KDC_SERVICE_EXP 2       /* Service expired */
#define         KDC_AUTH_EXP    3       /* Auth expired */
#define         KDC_PKT_VER     4       /* Protocol version unknown */
#define         KDC_P_MKEY_VER  5       /* Wrong master key version */
#define         KDC_S_MKEY_VER  6       /* Wrong master key version */
#define         KDC_BYTE_ORDER  7       /* Byte order unknown */
#define         KDC_PR_UNKNOWN  8       /* Principal unknown */
#define         KDC_PR_N_UNIQUE 9       /* Principal not unique */
#define         KDC_NULL_KEY   10       /* Principal has null key */
#define         KDC_GEN_ERR    20       /* Generic error from KDC */


/* Values returned by get_credentials */
#define         GC_OK           0       /* Retrieve OK */
#define         RET_OK          0       /* Retrieve OK */
#define         GC_TKFIL       21       /* Can't read ticket file */
#define         RET_TKFIL      21       /* Can't read ticket file */
#define         GC_NOTKT       22       /* Can't find ticket or TGT */
#define         RET_NOTKT      22       /* Can't find ticket or TGT */


/* Values returned by mk_ap_req  */
#define         MK_AP_OK        0       /* Success */
#define         MK_AP_TGTEXP   26       /* TGT Expired */

/* Values returned by rd_ap_req */
#define         RD_AP_OK        0       /* Request authentic */
#define         RD_AP_UNDEC    31       /* Can't decode authenticator */
#define         RD_AP_EXP      32       /* Ticket expired */
#define         RD_AP_NYV      33       /* Ticket not yet valid */
#define         RD_AP_REPEAT   34       /* Repeated request */
#define         RD_AP_NOT_US   35       /* The ticket isn't for us */
#define         RD_AP_INCON    36       /* Request is inconsistent */
#define         RD_AP_TIME     37       /* delta_t too big */
#define         RD_AP_BADD     38       /* Incorrect net address */
#define         RD_AP_VERSION  39       /* protocol version mismatch */
#define         RD_AP_MSG_TYPE 40       /* invalid msg type */
#define         RD_AP_MODIFIED 41       /* message stream modified */
#define         RD_AP_ORDER    42       /* message out of order */
#define         RD_AP_UNAUTHOR 43       /* unauthorized request */

/* Values returned by get_pw_tkt */
#define         GT_PW_OK        0       /* Got password changing tkt */
#define         GT_PW_NULL     51       /* Current PW is null */
#define         GT_PW_BADPW    52       /* Incorrect current password */
#define         GT_PW_PROT     53       /* Protocol Error */
#define         GT_PW_KDCERR   54       /* Error returned by KDC */
#define         GT_PW_NULLTKT  55       /* Null tkt returned by KDC */


/* Values returned by send_to_kdc */
#define         SKDC_OK         0       /* Response received */
#define         SKDC_RETRY     56       /* Retry count exceeded */
#define         SKDC_CANT      57       /* Can't send request */

/*
 * Values returned by get_intkt
 * (can also return SKDC_* and KDC errors)
 */

#define         INTK_OK         0       /* Ticket obtained */
#define         INTK_W_NOTALL  61       /* Not ALL tickets returned */
#define         INTK_BADPW     62       /* Incorrect password */
#define         INTK_PROT      63       /* Protocol Error */
#define         INTK_ERR       70       /* Other error */

/* Values returned by get_adtkt */
#define         AD_OK           0       /* Ticket Obtained */
#define         AD_NOTGT       71       /* Don't have tgt */

/* Error codes returned by ticket file utilities */
#define         NO_TKT_FIL      76      /* No ticket file found */
#define         TKT_FIL_ACC     77      /* Couldn't access tkt file */
#define         TKT_FIL_LCK     78      /* Couldn't lock ticket file */
#define         TKT_FIL_FMT     79      /* Bad ticket file format */
#define         TKT_FIL_INI     80      /* tf_init not called first */

/* Error code returned by kparse_name */
#define         KNAME_FMT       81      /* Bad Kerberos name format */

/* Error code returned by krb_mk_safe */
#define         SAFE_PRIV_ERROR -1      /* syscall error */

/*
 * macros for byte swapping; also scratch space
 * u_quad  0-->7, 1-->6, 2-->5, 3-->4, 4-->3, 5-->2, 6-->1, 7-->0
 * u_long  0-->3, 1-->2, 2-->1, 3-->0
 * u_short 0-->1, 1-->0
 */

#define     swap_u_16(x) {\
 unsigned long   _krb_swap_tmp[4];\
 _swab(((char *) x) +0, ((char *)  _krb_swap_tmp) +14 ,2); \
 _swab(((char *) x) +2, ((char *)  _krb_swap_tmp) +12 ,2); \
 _swab(((char *) x) +4, ((char *)  _krb_swap_tmp) +10 ,2); \
 _swab(((char *) x) +6, ((char *)  _krb_swap_tmp) +8  ,2); \
 _swab(((char *) x) +8, ((char *)  _krb_swap_tmp) +6 ,2); \
 _swab(((char *) x) +10,((char *)  _krb_swap_tmp) +4 ,2); \
 _swab(((char *) x) +12,((char *)  _krb_swap_tmp) +2 ,2); \
 _swab(((char *) x) +14,((char *)  _krb_swap_tmp) +0 ,2); \
 bcopy((char *)_krb_swap_tmp,(char *)x,16);\
                            }

#define     swap_u_12(x) {\
 unsigned long   _krb_swap_tmp[4];\
 _swab(( char *) x,     ((char *)  _krb_swap_tmp) +10 ,2); \
 _swab(((char *) x) +2, ((char *)  _krb_swap_tmp) +8 ,2); \
 _swab(((char *) x) +4, ((char *)  _krb_swap_tmp) +6 ,2); \
 _swab(((char *) x) +6, ((char *)  _krb_swap_tmp) +4 ,2); \
 _swab(((char *) x) +8, ((char *)  _krb_swap_tmp) +2 ,2); \
 _swab(((char *) x) +10,((char *)  _krb_swap_tmp) +0 ,2); \
 bcopy((char *)_krb_swap_tmp,(char *)x,12);\
                            }

#define     swap_C_Block(x) {\
 unsigned long   _krb_swap_tmp[4];\
 _swab(( char *) x,    ((char *)  _krb_swap_tmp) +6 ,2); \
 _swab(((char *) x) +2,((char *)  _krb_swap_tmp) +4 ,2); \
 _swab(((char *) x) +4,((char *)  _krb_swap_tmp) +2 ,2); \
 _swab(((char *) x) +6,((char *)  _krb_swap_tmp)    ,2); \
 bcopy((char *)_krb_swap_tmp,(char *)x,8);\
                            }
#define     swap_u_quad(x) {\
 unsigned long   _krb_swap_tmp[4];\
 _swab(( char *) &x,    ((char *)  _krb_swap_tmp) +6 ,2); \
 _swab(((char *) &x) +2,((char *)  _krb_swap_tmp) +4 ,2); \
 _swab(((char *) &x) +4,((char *)  _krb_swap_tmp) +2 ,2); \
 _swab(((char *) &x) +6,((char *)  _krb_swap_tmp)    ,2); \
 bcopy((char *)_krb_swap_tmp,(char *)&x,8);\
                            }

#define     swap_u_long(x) {\
 unsigned long   _krb_swap_tmp[4];\
 _swab((char *)  &x,    ((char *)  _krb_swap_tmp) +2 ,2); \
 _swab(((char *) &x) +2,((char *)  _krb_swap_tmp),2); \
 x = _krb_swap_tmp[0];   \
                           }

#define     swap_u_short(x) {\
 unsigned short _krb_swap_sh_tmp; \
 _swab((char *)  &x,    ( &_krb_swap_sh_tmp) ,2); \
 x = (unsigned short) _krb_swap_sh_tmp; \
                            }

/* Kerberos ticket flag field bit definitions */
#define K_FLAG_ORDER    0       /* bit 0 --> lsb */
#define K_FLAG_1                /* reserved */
#define K_FLAG_2                /* reserved */
#define K_FLAG_3                /* reserved */
#define K_FLAG_4                /* reserved */
#define K_FLAG_5                /* reserved */
#define K_FLAG_6                /* reserved */
#define K_FLAG_7                /* reserved, bit 7 --> msb */

char *tkt_string();

#ifdef  OLDNAMES
#define krb_mk_req      mk_ap_req
#define krb_rd_req      rd_ap_req
#define krb_kntoln      an_to_ln
#define krb_set_key     set_serv_key
#define krb_get_cred    get_credentials
#define krb_mk_priv     mk_private_msg
#define krb_rd_priv     rd_private_msg
#define krb_mk_safe     mk_safe_msg
#define krb_rd_safe     rd_safe_msg
#define krb_mk_err      mk_appl_err_msg
#define krb_rd_err      rd_appl_err_msg
#define krb_ck_repl     check_replay
#define krb_get_pw_in_tkt       get_in_tkt
#define krb_get_svc_in_tkt      get_svc_in_tkt
#define krb_get_pw_tkt          get_pw_tkt
#define krb_realmofhost         krb_getrealm
#define krb_get_phost           get_phost
#define krb_get_krbhst          get_krbhst
#define krb_get_lrealm          get_krbrlm
#endif  /* OLDNAMES */

/* Defines for krb_sendauth and krb_recvauth */

#define KOPT_DONT_MK_REQ 0x00000001 /* don't call krb_mk_req */
#define KOPT_DO_MUTUAL   0x00000002 /* do mutual auth */

#define KOPT_DONT_CANON  0x00000004 /*
                                     * don't canonicalize inst as
                                     * a hostname
                                     */

#define KRB_SENDAUTH_VLEN 8         /* length for version strings */

#ifdef ATHENA_COMPAT
#define KOPT_DO_OLDSTYLE 0x00000008 /* use the old-style protocol */
#endif /* ATHENA_COMPAT */

#ifdef WINDOWS
#include <lsh_pwd.h>
int gettimeofday(struct timeval *tv, struct timezone *tz);
void tkt_free(tkt_header FAR* hdr);
int krb_get_tf_fullname(char *tf, char *name, char *inst, char *realm);
/*      Windows prototypes */
int FAR PASCAL krb_sendauth(long,int,KTEXT_FP,LPSTR,LPSTR,LPSTR,unsigned long,
        MSG_DAT FAR *,CREDENTIALS FAR *, Key_schedule FAR *,
        struct sockaddr_in FAR *,struct sockaddr_in FAR *, LPSTR);
char FAR* FAR* FAR get_krb_err_txt(void);
/* 2-22-93, pbh */
int FAR krb_get_tf_realm(char FAR *,char FAR *);
int FAR tf_init(char FAR*,int);
int FAR tf_get_pname(char FAR*);
int FAR tf_get_pinst(char FAR*);
int FAR tf_get_cred(CREDENTIALS FAR*);
void FAR tf_close(void);
int FAR tf_save_cred(char FAR*,char FAR*,char FAR*,C_Block,int,int,KTEXT,long);
BOOL FAR k_isinst(char FAR *s);
BOOL FAR k_isrealm(char FAR *s);
BOOL FAR k_isname(char FAR *s);
int FAR set_krb_debug( int );   /* Warning, unique to Windows! */
int FAR set_krb_ap_req_debug( int );    /* Warning, unique to Windows! */
LPSTR FAR PASCAL get_krb_err_txt_entry( int i);           /* Warning, unique to Windows! */
int FAR PASCAL krb_mk_req(KTEXT,LPSTR,LPSTR,LPSTR,long);
LPSTR FAR PASCAL krb_getrealm( char FAR *host);
/* end 2-22-93, pbh */

#ifdef WINSOCK
#define bcopy(a,b,c) memcpy( (b), (a), (c) )
#define bzero(a,b) memset( (a), 0, (b) )
#endif /* WINSOCK */


/*
#ifdef __cplusplus
int printf(char far*,...);
#else
int printf();
#endif
*/

int FAR kname_parse(char FAR*,char FAR*,char FAR*,char FAR*);
int FAR krb_get_pw_in_tkt(char FAR*,char FAR*,char FAR*,char FAR*,char FAR*,int,char FAR*);
int FAR dest_tkt(void);
int FAR krb_get_lrealm(LPSTR ,int);

int FAR krb_use_kerbmem();
int FAR krb_check_tgt();
int FAR krb_check_serv(char *);

int FAR krb_get_cred(char FAR*,char FAR*,char FAR*,CREDENTIALS FAR*);
int FAR send_to_kdc(KTEXT,KTEXT,char FAR*);

#define MIT_PWD_DLL_CLASS "MITPasswordWndDLL"

#else  /* end of WINDOWS start of DOS */

/*      DOS prototypes */
int krb_get_in_tkt(char *, char *, char *, char *, char *, int, int (*)(), int (*)(), char *);
long krb_mk_priv( u_char *, u_char *, u_long, Key_schedule, C_Block,
                  struct sockaddr_in *, struct sockaddr_in *);
char* krb_getrealm( char *host);
char* krb_realmofhost( char *host);
int krb_get_tf_realm(char*,char*);
int krb_get_tf_fullname(char*,char*,char*,char*);
int get_ad_tkt(char*,char*,char*,int);
int krb_get_cred(char*,char*,char*,CREDENTIALS*);
int krb_get_krbhst(char*,char*,int);
int krb_get_lrealm(char*,int);
char* krb_get_phost(char*);
int krb_mk_req(KTEXT,char*,char*,char*,long);
int krb_set_lifetime(int);

#ifndef WINSOCK
int krb_net_read(int,char*,int);
int krb_net_write(int,char*,int);
#else
int krb_net_read(SOCKET,char*,int);
int krb_net_write(SOCKET,char*,int);
#endif /*winsock*/

KTEXT pkt_cipher(KTEXT);
int pkt_clen(KTEXT);
long krb_rd_priv(unsigned char*,unsigned long,Key_schedule,C_Block,
                                struct sockaddr_in*, struct sockaddr_in*,MSG_DAT*);
int save_credentials(char*,char*,char*,C_Block,int,int,KTEXT,long);
int send_to_kdc(KTEXT,KTEXT,char*);
int krb_sendauth(long,int,KTEXT,char*,char*,char*,u_long,
    MSG_DAT*,CREDENTIALS*,Key_schedule,
        struct sockaddr_in*,struct sockaddr_in*,char*);
int tf_init(char*,int);
int tf_get_pname(char*);
int tf_get_pinst(char*);
int tf_get_cred(CREDENTIALS*);
void tf_close(void);
int tf_save_cred(char*,char*,char*,C_Block,int,int,KTEXT,long);
int kname_parse(char*,char*,char*,char*);
int krb_get_pw_in_tkt(char*,char*,char*,char*,char*,int,char*);
int dest_tkt(void);

int krb_use_kerbmem();
int krb_check_tgt();
int krb_check_serv(char *);

#endif  /* WINDOWS */
#endif  /* KRB_DEFS */

/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* tgeneral.h.                                                              *
*                                                                          *
* Function:..General-Headerfile for TWEB                                   *
*                                                                          *
*                                                                          *
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
 * $Id: tgeneral.h,v 1.8 1999/09/13 13:47:47 zrnsk01 Exp $
 *
 */


#ifndef _TGENERAL_
#define _TGENERAL_

#define PUBLIC
#define PRIVATE static

/* For changes see file CHANGES */
#ifdef __hpux
#define _INCLUDE_POSIX_SOURCE
#define _INCLUDE_XOPEN_SOURCE
#define _INCLUDE_HPUX_SOURCE
#define TIOCNOTTY   _IO('t', 113)
#define getdtablesize() _NFILE
#endif

#if defined( __linux__ ) && !defined( _BSD_SOURCE )
#define  _BSD_SOURCE
#define  _SVID_SOURCE
#define  _GNU_SOURCE
#define  _POSIX_SOURCE
#endif

#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include "lber.h"
#include "ldap.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/*  Support of LDAP API versions */
#if LDAP_API_VERSION >= 2003 && LDAP_API_VERSION <= 2010
#define OL_LDAPV		3
#else
#  if LDAP_API_VERSION >= 2001 && LDAP_API_VERSION <= 2010
#  define OL_LDAPV		2
#  else
#    define OL_LDAPV	0
#  endif
#endif

#  define ldap_debug debug

#if OL_LDAPV > 2
#  include "portable.h"
#  include "ldap_log.h"
#endif

extern   int   errno;


#include "strng_exp.h"

#ifndef TRUE
#define TRUE   1
#endif
#ifndef FALSE
#define FALSE  0
#endif
#define OK     1
#define NOTOK  0
#define DONE -1
#define  _TIMEOUT_LEN   31
#define  _LOG_TIME     "%a, %d.%m.%y, %H:%M:%S"

#include "init_exp.h"
extern GLOB_STRUCT *globP;

/*
 ***************************************************************************
 * If you are not a University of Tuebingen site, 
 * you probably want to tailor the following:
 ***************************************************************************
 */

/* Special code for DFN-Project AMBIX-D */
#ifdef AMBIXGW

#  define SELBST_CN          glob->selbsteintrag[0]
#  define SELBST_CN_NAME     glob->selbsteintrag[1]
#  define SELBST_STUDIE_ATTR glob->selbsteintrag[2]
#  define SELBST_INSERT_MODE glob->selbsteintrag[3]
#  define SELBST_INSERT_WHO  glob->selbsteintrag[4]
#  define SELBST_INSERT_NO   glob->selbsteintrag[5]
#  define SELBST_INSERT_WORK glob->selbsteintrag[6]
#  define SELBST_INSERT_ALL  glob->selbsteintrag[7]
#  define SELBST_INSERT_STUD glob->selbsteintrag[8]

#  define MAXDN_LEN 2048

extern void self_insert();

#endif



/* Flags for print_attr */
#define DEFAULT        0
#define MULTILINE      1
#define HREF           2
#define FINGER         3
#define DATE           4
#define URL            5
#define MAILTO         6
#define MOVETO         7
#define BMP            8
#define JPEG           9
#define JPEG2GIF      10
#define BOOLEAN       11
#define URI           12
#define PGPKEY        13
#define INDEXURL      14
#define DYNAMICDN     15
#define REFERRAL      20
#define PRE           21
#define HEADER        22

#ifdef TUE_TEL
#define PHONREFSHORT  16
#define PHONREFLONG   17
#define TFUNCPERS     18
#define FAXTABLE      19
#endif


/* Patch for hpux from ksp: */
#ifdef __hpux
#  define rewind(a) fflush(a)
#endif

#define G3TOXBM "cat"
#define JPEGTOGIF "/soft/bin/djpeg -gif"

/*
 *************************************************************************
 * The rest of this stuff probably does not need to be changed
 *************************************************************************
 */

#define TIMEOUT        240
#define WEB500PORT    8889

#ifndef FD_SET
#define NFDBITS         32
#define FD_SETSIZE      32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif

#define from_hex(c)    ((c>='0')&&(c<='9') ? c-'0' : (c>='A')&&(c<='F') ?\
            c-'A'+10 : (c>='a')&&(c<='f') ? c-'a'+10 : 0)

/*
 * HTTP request we are implementing
 */

#define    UNKNOWN    0
#define    GET        1
#define    HEAD       2

/*
 * HTTP response status
 */
#define DOCUMENT_FOLLOWS  200
#define REDIRECT          302
#define BAD_REQUEST       400
#define AUTH_REQUIRED     401
#define FORBIDDEN         403
#define NOT_FOUND         404
#define SERVER_ERROR      500
#define NOT_IMPLEMENTED   501

#define PRINT_HTML_HEADER     (fprintf(fp, \
"HTTP/1.0 %d Document follows\n\
MIME-Version: 1.0\n\
Server: %s\n\
Date: %s\n\
Content-Type: text/html\n\
Last-Modified: %s\n\
%s\n",\
DOCUMENT_FOLLOWS, version, glob->nowtimestr, glob->nowtimestr,\
 glob->caching ? glob->expiretimestr : "Pragma: no-cache\n" ))

#define PRINT_PLAIN_HEADER     (fprintf(fp, \
"HTTP/1.0 %d Document follows\n\
MIME-Version: 1.0\n\
Server: %s\n\
Date: %s\n\
Content-Type: text/plain\n\
Last-Modified: %s\n\
%s\n",\
DOCUMENT_FOLLOWS, version, glob->nowtimestr, glob->nowtimestr,\
 glob->caching ? glob->expiretimestr : "Pragma: no-cache\n" ))

#define PRINT_REDIRECT_HEADER     (fprintf(fp, \
"HTTP/1.0 302 Found\n\
MIME-Version: 1.0\n\
Server: %s\n\
Date: %s\n\
Location: %s\n\
Content-Type: text/html\n\
Last-Modified: %s\n\
%s\n",\
version, glob->nowtimestr, query, glob->nowtimestr,\
 glob->caching ? glob->expiretimestr : "Pragma: no-cache\n" ))

#define HTML_HEAD_TITLE "<HTML><HEAD><TITLE>%s</TITLE></HEAD><%s>"

#define PRINT_HTML_FOOTER     (fprintf(fp, "</BODY></HTML>"))

/* Meta-Syntax of Gateway-Switching feature */
#define GWS        "(gw)"
#define GWS_FORMAT "(gw-%s)"


#define OUT_TIME 900

/* Separator in UFNs */
#define UFNSEP ","

#endif /* _TGENERAL_ */


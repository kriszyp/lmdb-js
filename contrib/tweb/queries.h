/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* queries.h..                                                              *
*                                                                          *
* Funktion:..WorldWideWeb-X.500-Gateway - Server-Functions                 *
*            Based on web500gw.c 1.3 written by Frank Richter, TU Chemmniz *
*            which is based on go500gw by Tim Howes, University of         *
*            Michigan  - All rights reserved                               *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:    :           Z   D  D   V   V                *
*            August 16 1995               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            May 10 1999                ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: queries.h,v 1.6 1999/09/10 15:01:18 zrnsk01 Exp $
 *
 */

#ifndef _QUERIES_
#define _QUERIES_

#include "tgeneral.h"
#include "tglobal.h"
#include "init_exp.h"
#include "checkclient_exp.h"
#include "support_exp.h"

#include "queries_exp.h"
#include "x500_exp.h"
#include "html_exp.h"
#include "server_exp.h"
#include "dn_exp.h"
#include "charray_exp.h"

#ifdef TUE_TEL
#include "tueTel_exp.h"
#endif


/*  Macros for request-recognition */

/*  1. without DSA */
#define cHELP         'H'
#define cERROR        'E'
#define cCONFIG       'C'
#define cSTATS        'K'
#define cPULLDOWN     'D'
#define cBUTTON       'B'

/*  2. with user-bind */
#define cGETMOD       'F'
#define cDOMOD        'Y'

/*  3. with GW-bind */
#define cREAD         'R'
#define cREADALL      'L'
#define cSEARCH       'S'
#define cLIST         'M'
#ifdef TUE_TEL
#define cTON          'T'
#endif
#define cGIF          'I'
#define cJPEG         'J'
#define cG3FAX        'G'
#define cAUDIO        'A'
#define cREFERRAL     'W'
#define cEXTENDED     'X'

#define GMT_FORMAT "%a, %d %b %Y %T GMT"
#define GMT_FORMAT2 "Expires: %a, %d %b %Y %T GMT\n"
#define ROBOTS_TXT_FILE "robots.txt"

PRIVATE void strict_basednf();
PRIVATE void trade_cache();

#endif /* _QUERIES_ */


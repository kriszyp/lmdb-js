/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* server.h...                                                              *
*                                                                          *
* Funktion:..WorldWideWeb-X.500-Gateway - Server-Funktions                 *
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
*            December 31 1998           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: server.h,v 1.6 1999/09/10 15:01:19 zrnsk01 Exp $
 *
 */

#ifndef _SERVER_
#define _SERVER_

#include "server_exp.h"
#include "queries_exp.h"
#include "support_exp.h"

#ifdef TUE_TEL
#include "tueTel_exp.h"
#endif


#define CARRSIZE 8192

#define MASK_30 0x40000000
#define MASK_20 0x00100000
#define MASK_17 0x00020000
#define MASK_10 0x00000ffc

#define IP_HACK(x)    ((((MASK_30 & (x)) != 0) * 4096) + \
                       (((MASK_20 & (x)) != 0) * 2048) + \
                       (((MASK_17 & (x)) != 0) * 1024) + \
                       ((MASK_10 & (x)) >> 2))

/* three integer-arrays to count connections */
int conArr[CARRSIZE];
unsigned long int shadowconArr[CARRSIZE];
unsigned long int sumconArr[CARRSIZE];

/* the signal-handler */
PRIVATE void reset_conMem();

/* set the Alarm-Timer */
PRIVATE void    hackTimer();

PRIVATE int set_socket();
PRIVATE void wait4child();

/*  A pointer to the Anti-Hack-infos in the Glob-structure */
COMREFUSE  *comRefuseP = NULL;
time_t *stat_slice;


#endif /* _SERVER_ */



/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* dn.h.......                                                              *
*                                                                          *
* Function:..Header-Datei fuer TWEB-Software                               *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            April 24 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            November 21 1996           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: dn.h,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#ifndef _DN_
#define _DN_

#define DNSEPARATOR(c)  (c == ',' || c == ';')
#define SEPARATOR(c)    (c == ',' || c == ';' || c == '+')
#define SPACE(c)        (c == ' ' || c == '\n')
#define NEEDSESCAPE(c)  (c == '\\' || c == '"')
#define B4TYPE          0
#define INTYPE          1
#define B4EQUAL         2
#define B4VALUE         3
#define INVALUE         4
#define INQUOTEDVALUE   5
#define B4SEPARATOR     6

#include "dn_exp.h"

#endif /* _DN_ */

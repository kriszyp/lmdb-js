/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* checkclient.h                                                            *
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
*            March 18 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            March 19 1999              ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: checkclient.h,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */
#include "checkclient_exp.h"
#include "regular_exp.h"
#include "support_exp.h"
#include "x500_exp.h"
#include "charray_exp.h"
#include "ch_malloc_exp.h"

#ifndef _CHECKCLIENT_
#define _CHECKCLIENT_

#define PROXY_TOKEN1 " via "
#define PROXY_TOKEN2 "gateway"

PRIVATE int checkad();
PRIVATE int check4access();

#endif /* _CHECKCLIENT_ */

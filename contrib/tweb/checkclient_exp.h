/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* checkclient_exp.h                                                        *
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
 * $Id: checkclient_exp.h,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#ifndef _CHECKCLIENT_EXP_
#define _CHECKCLIENT_EXP_

PUBLIC void checkwwwclient();
PUBLIC void decide_access();
PUBLIC void get_ip_refuse_clients();
PUBLIC int  check_ip_denial();
PUBLIC void re_readIPrefuse();

#endif /* _CHECKCLIENT_EXP_ */

/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* charray_exp.h                                                            *
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
*            April 16 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            November 21 1996           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: charray_exp.h,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#ifndef _CHARRAY_EXP_
#define _CHARRAY_EXP_

PUBLIC void charray_add();
PUBLIC void charray_merge();
PUBLIC void charray_free();
PUBLIC int charray_inlist();
PUBLIC char ** charray_dup();
PUBLIC char ** str2charray();


#endif /* _CHARRAY_EXP_ */

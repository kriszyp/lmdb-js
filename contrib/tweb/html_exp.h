/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* html_exp.h.                                                              *
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
*            February 13 1996             Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            November 21 1996           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: html_exp.h,v 1.6 1999/09/10 15:01:17 zrnsk01 Exp $
 *
 */

#ifndef _HTML_EXP_
#define _HTML_EXP_

PUBLIC void print_attr(/*ld, fp, dn, label, tattr, e, flag, doNotShow, glob*/);
PUBLIC void form_attr(/*ld, fp, label, tattr, e, multiline, add_empty, glob*/);
PUBLIC void do_pict(/*ld, fp, dn, type, glob*/);
PUBLIC void do_audio(/*ld, fp, dn, type, glob*/);
PUBLIC void do_sizelimit(/*fp, type, glob*/);
PUBLIC void do_error(/*fp, code, status, glob*/);
PUBLIC void explain_error (/*fp, error, status, glob */);
PUBLIC void make_header (/*fp, dn, action, glob*/);
PUBLIC char * url_complete (/*gwp_url, rdn, separator*/);



#endif /* _HTML_EXP_ */

/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* x500_exp.h.                                                              *
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
*            February 13 1996             Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            January 10 1999            ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: x500_exp.h,v 1.6 1999/09/10 15:01:21 zrnsk01 Exp $
 *
 */

#ifndef _X500_EXP_
#define _X500_EXP_

PUBLIC void do_menu(/*ld, fp, dn, glob*/);
PUBLIC void do_xtend(/*ld, fp, dn, glob*/);
PUBLIC int do_search(/*ld, fp, query, glob*/);
PUBLIC void do_read(/*ld, fp, dn, amore, glob*/);
PUBLIC void do_form(/*ld, fp, query, glob*/);
PUBLIC void do_modify(/*ld, fp, query, glob*/);
PUBLIC char * make_oc_to_string(/*oc*/);
PUBLIC LDAP *get_ldap_connection( /* host, port, glob */ );
PUBLIC void close_ldap_connections();


#endif /* _X500_EXP_ */

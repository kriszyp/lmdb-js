/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* x500.h.....                                                              *
*                                                                          *
* Function:..Header-File for TWEB-Software                                 *
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
*            February 18 1999           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: x500.h,v 1.6 1999/09/10 15:01:21 zrnsk01 Exp $
 *
 */

#ifndef _X500_
#define _X500_

#include "x500_exp.h"
#include "charray_exp.h"
#include "ch_malloc_exp.h"

typedef LDAPMessage *(*LFP)();

typedef struct _my_ldap_list {
    LDAPMessage *e;
    struct _my_ldap_list *next;
} MY_LDAP_LIST, *pMY_LDAP_LIST;

pMY_LDAP_LIST mllroot = NULL;

PRIVATE int compare(/*a,b*/);
PRIVATE char * pick_oc(/*oclist*/);
PRIVATE int make_scope(/*ld, dn, glob*/);
PRIVATE int no_show(/* rdn, glob*/);
PRIVATE int sort_result(/*ld, res, dn, no_browse, glob*/);
PRIVATE void list_output(/*fp, flag, glob*/);
PRIVATE void make_la_buttons(/*sep, fp, dn, la_url, glob*/);
PRIVATE void make_la_buttons_pull_down(/*sep, fp, dn, la_url, glob*/);
PRIVATE void print_rdn(/*fp, dn, glob*/);
PRIVATE void print_rdn_pull_down(/*fp, dn, glob*/);
PRIVATE void make_search_box(/*fp, ld, dn, glob*/);
PRIVATE LDAPMessage *my_first_entry();
PRIVATE LDAPMessage *my_next_entry();
PRIVATE LDAPMessage *ldap_list_eval();
PRIVATE void sort_parse();
PRIVATE void get_ref_attrs();
PRIVATE void disp_form_button();


#endif /* _X500_ */

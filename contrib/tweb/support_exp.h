/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* support_exp.h                                                            *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway - Supporting Routines              *
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
*            December 2 1995              Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            September 7 1999           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: support_exp.h,v 1.6 1999/09/10 15:01:20 zrnsk01 Exp $
 *
 */

#ifndef _SUPPORT_EXP_H_
#define _SUPPORT_EXP_H_

PUBLIC char * hex_decode ();
PUBLIC char * hex_qdecode ();
PUBLIC char * form_encode ();

PUBLIC char * format_date ();
PUBLIC char * friendly_dn ();
PUBLIC char * format_time ();
PUBLIC char * strQuoteChr();
PUBLIC int    strlstcmp (/* char *s1, char *s2, char sep */);
PUBLIC void   re_fail ();
PUBLIC char *dnrcut(/*rdn, target, basecount*/);
PUBLIC void  disp_file (/* GLOB_STRUCT glob, char *filename, FILE *fp */);

PUBLIC char *elapsed();

PUBLIC char *hex_html_encode();

#define hex_encode(x) hex_html_encode((x), 0)
#define char2html(x) hex_html_encode((x), 1)
#define flatten_chars(x) hex_html_encode((x), 2)

PUBLIC char * get_parentDN();
PUBLIC char **dn2charray();
PUBLIC char * strrQuoteChr();
PUBLIC int exit_tweb();


/*  dn_cmp and return codes  */
PUBLIC int dn_cmp( /* dn1, dn2 */ );
PUBLIC int dn_cmp_parts( /* dn1, dn2, &matched */ );
#define DN_EQUAL       0       /*  dns are exactly equal            */
#define DN_LESS       -1       /*  dn1 is part of dn2               */
#define DN_GREATER     1       /*  dn2 is part of dn1               */
#define DN_UNMATCHED  -2       /*  dns differ, matched is the same  */
                               /*    (matched as seen from c down)  */


#endif


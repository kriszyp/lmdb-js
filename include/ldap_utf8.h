/* $OpenLDAP$ */
/* $Novell: /ldap/src/cldap/include/ldap_utf8.h,v 1.3 2000/12/04 20:23:20 dsteck Exp $ 
/*
 * Copyright 2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/******************************************************************************
 * This notice applies to changes, created by or for Novell, Inc.,
 * to preexisting works for which notices appear elsewhere in this file.
 *
 * Copyright (C) 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
 * USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT TO VERSION
 * 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS AVAILABLE AT
 * HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE" IN THE
 * TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION OF THIS
 * WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP PUBLIC
 * LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT THE
 * PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY. 
 ******************************************************************************/

#ifndef _LDAP_UTF8_H
#define _LDAP_UTF8_H

LDAP_BEGIN_DECL

/*  
 * UTF-8 Utility Routines (in utf-8.c)
 */

#define LDAP_UCS4_INVALID (0x80000000U)

/* LDAP_MAX_UTF8_LEN is 3 or 6 depending on size of wchar_t */
#define LDAP_MAX_UTF8_LEN  sizeof(wchar_t)*3/2


/*
 * UTF-8 Conversion Routines.   (in utfconv.c)
 */

/* UTF-8 character to Wide Char */
LDAP_F(int)
ldap_x_utf8_to_wc ( wchar_t *wchar, const char *utf8char );

/* UTF-8 string to Wide Char string */
LDAP_F(int)
ldap_x_utf8s_to_wcs ( wchar_t *wcstr, const char *utf8str, size_t count );

/* Wide Char to UTF-8 character */
LDAP_F(int)
ldap_x_wc_to_utf8 ( char *utf8char, wchar_t wchar, size_t count );

/* Wide Char string to UTF-8 string */
LDAP_F(int)
ldap_x_wcs_to_utf8s ( char *utf8str, const wchar_t *wcstr, size_t count );


/* UTF-8 character to MultiByte character */
LDAP_F(int)
ldap_x_utf8_to_mb ( char *mbchar, const char *utf8char,
		int (*f_wctomb)(char *mbchar, wchar_t wchar) );

/* UTF-8 string to MultiByte string */
LDAP_F(int)
ldap_x_utf8s_to_mbs ( char *mbstr, const char *utf8str, size_t count,
		size_t (*f_wcstombs)(char *mbstr, const wchar_t *wcstr, size_t count) );

/* MultiByte character to UTF-8 character */
LDAP_F(int)
ldap_x_mb_to_utf8 ( char *utf8char, const char *mbchar, size_t mbsize,
		int (*f_mbtowc)(wchar_t *wchar, const char *mbchar, size_t count) );

/* MultiByte string to UTF-8 string */
LDAP_F(int)
ldap_x_mbs_to_utf8s ( char *utf8str, const char *mbstr, size_t count,
		size_t (*f_mbstowcs)(wchar_t *wcstr, const char *mbstr, size_t count) );

LDAP_END_DECL

#endif /* _LDAP_UTF8_H */

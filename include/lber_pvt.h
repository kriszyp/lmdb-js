/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/*
 * lber_pvt.h - Header for ber_pvt_ functions. These are meant to be used
 * 		by the OpenLDAP distribution only.
 */

#ifndef _LBER_PVT_H
#define _LBER_PVT_H 1

#include <lber.h>

LDAP_BEGIN_DECL

#ifdef __MINGW32__
#   undef LDAP_F_PRE
#   ifdef LIBLBER_DECL
#	define LDAP_F_PRE	extern __declspec(LIBLBER_DECL)
#   else
#	define LDAP_F_PRE	extern
#   endif
#endif

/*
 * bprint.c
 */
LDAP_F( BER_LOG_PRINT_FN ) ber_pvt_log_print;

LDAP_F( int )
ber_pvt_log_printf LDAP_P((
	int errlvl,
	int loglvl,
	const char *fmt,
	... )) LDAP_GCCATTR((format(printf, 3, 4)));

LDAP_END_DECL

#endif


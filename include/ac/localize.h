/* localize.h (i18n/l10n) */
/* $OpenLDAP$ */
/*
 * Copyright 2003 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */

#ifndef _AC_LOCALIZE_H
#define _AC_LOCALIZE_H

#ifdef LDAP_LOCALIZE
#	include <locale.h>
#	include <libintl.h>

	/* enable i18n/l10n */
#	define gettext_noop(s)		s
#	define _(s)					gettext(s)
#	define N_(s)				gettext_noop(s)

#else
	/* disable i18n/l10n */
#	define setlocale(c,l)		/* empty */ 

#	define _(s)					s
#	define N_(s)				s
#	define textdomain(d)		/* empty */
#	define bindtextdomain(p,d)	/* empty */

#endif

#endif /* _AC_LOCALIZE_H */

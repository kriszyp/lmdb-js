/* Generic assert.h */
/*
 * Copyright 1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_ASSERT_H
#define _AC_ASSERT_H

#ifdef LDAP_DEBUG

#if defined( HAVE_ASSERT_H ) || defined( STDC_HEADERS )
#undef NDEBUG
#include <assert.h>
#else
#define LDAP_NEED_ASSERT 1

/*
 * no assert()... must be a very old compiler.
 * create a replacement and hope it works
 */

void	ber_pvt_assert(char* file, int line, char* test);
#define assert(test) \
	((test) \
		? (void)0 \
		: ber_pvt_assert( __FILE__, __LINE__, LDAP_STRING(test)) )

#endif

#else
/* no asserts */
#define assert(test) ((void)0)
#endif

#endif /* _AC_ASSERT_H */

/* $OpenLDAP$ */
/*
 * Copyright 1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#ifdef LDAP_NEED_ASSERT

#include <stdio.h>

/*
 * helper for our private assert() macro
 *
 * note: if assert() doesn't exist, like abort() or raise() won't either.
 * could use kill() but that might be problematic.  I'll just ignore this
 * issue for now.
 */

void
ber_pvt_assert( const char *file, int line, const char *test )
{
	fprintf(stderr,
		"Assertion failed: %s, file %s, line %d\n",
			test, file, line);

	abort();
}

#endif

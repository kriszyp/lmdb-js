/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/* File locking methods */

#ifndef _LUTIL_LOCKF_H_
#define _LUTIL_LOCKF_H_

#include <stdio.h>
#include <ldap_cdefs.h>
#include <ac/bytes.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef NEED_FCNTL_LOCKING
LDAP_BEGIN_DECL

LDAP_F int lutil_ldap_lockf LDAP_P(( FILE *fs ));
LDAP_F int lutil_ldap_unlockf LDAP_P(( FILE *fs ));

LDAP_END_DECL
#endif /* NEED_FCNTL_LOCKING */

#endif /* _LUTIL_LOCKF_H_ */

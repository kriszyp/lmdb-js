/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#ifndef _BACK_PASSWD_H
#define _BACK_PASSWD_H

#include "external.h"

LDAP_BEGIN_DECL

extern ldap_pvt_thread_mutex_t passwd_mutex;

LDAP_END_DECL

#endif /* _BACK_PASSWD_H */

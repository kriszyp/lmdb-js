/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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

#ifndef _BDB_EXTERNAL_H
#define _BDB_EXTERNAL_H

#ifndef _PROTO_BDB_H
#error "\"proto-bdb.h\" must be included first"
#endif /* _PROTO_BDB_H */

/*

#include "proto-bdb.h"

 * must be included first
 */

LDAP_BEGIN_DECL

#define bdb_back_initialize		BDB_SYMBOL(back_initialize)

extern BI_init				bdb_back_initialize;

LDAP_END_DECL

#endif /* _BDB_EXTERNAL_H */


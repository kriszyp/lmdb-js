/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 Howard Chu @ Symas Corp.
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
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#ifndef _HDB_EXTERNAL_H
#define _HDB_EXTERNAL_H

#ifndef BDB_HIER
#define BDB_HIER
#endif

extern BI_init	hdb_initialize;

#include "../back-bdb/external.h"

#endif /* _HDB_EXTERNAL_H */


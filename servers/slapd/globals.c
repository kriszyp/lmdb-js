/* globals.c - various global variables */
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include "lber_pvt.h"

#include "slap.h"


/*
 * global variables, in general, should be declared in the file
 * primarily responsible for its management.  Configurable globals
 * belong in config.c.  variables declared here have no other
 * sensible home.
 */

const struct berval slap_empty_bv = BER_BVC("");
const struct berval slap_unknown_bv = BER_BVC("unknown");

/* normalized boolean values */
const struct berval slap_true_bv = BER_BVC("TRUE");
const struct berval slap_false_bv = BER_BVC("FALSE");

//struct sync_cookie *slap_sync_cookie = NULL;
struct slap_sync_cookie_s slap_sync_cookie =
			LDAP_STAILQ_HEAD_INITIALIZER( slap_sync_cookie );

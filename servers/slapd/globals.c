/* globals.c - various global variables */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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

struct sync_cookie *slap_sync_cookie = NULL;

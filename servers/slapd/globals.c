/* globals.c - various global variables */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include "slap.h"

/*
 * global variables, in general, should be declared in the file
 * primarily responsible for its management.  Configurable globals
 * belong in config.c.  variables declared here have no other
 * sensible home.
 */

const struct berval slap_empty_bv = { 0, "" };


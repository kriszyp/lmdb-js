/* lcup.c - lcup operations */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "slap.h"

#ifdef LDAP_CLIENT_UPDATE

AttributeName uuid_attr[2];

int
build_uuid_attr()
{
        const char* text;

	uuid_attr[0].an_name.bv_len = 9;
	uuid_attr[0].an_name.bv_val = "entryUUID";
	uuid_attr[1].an_name.bv_len = 0;
	uuid_attr[1].an_name.bv_val = NULL;
	uuid_attr[0].an_desc = NULL;
	uuid_attr[0].an_oc = NULL;
	uuid_attr[1].an_desc = NULL;
	uuid_attr[1].an_oc = NULL;
	slap_bv2ad(&uuid_attr[0].an_name, &uuid_attr[0].an_desc, &text);
}

#endif

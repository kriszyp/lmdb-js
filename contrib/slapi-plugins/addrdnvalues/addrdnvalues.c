/*
 * Copyright 2003-2004 PADL Software Pty Ltd.
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
/* (C) Copyright PADL Software Pty Ltd. 2003
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that this notice is preserved
 * and that due credit is given to PADL Software Pty Ltd. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include <string.h>
#include <unistd.h>

#include <ldap.h>
#include <lber.h>

#include <slapi-plugin.h>

int addrdnvalues_preop_init(Slapi_PBlock *pb);

static Slapi_PluginDesc pluginDescription = {
	"addrdnvalues-plugin",
	"PADL",
	"1.0",
	"RDN values addition plugin"
};

static int addrdnvalues_preop_add(Slapi_PBlock *pb)
{
	int rc;
	Slapi_Entry *e;
	char *szDN;
	LDAPDN dn;
	int i;

	if (slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, "addrdnvalues_preop_add",
				"Error retrieving target entry\n");
		return -1;
	}

	szDN = slapi_entry_get_dn(e);
	rc = ldap_str2dn(szDN, &dn, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		slapi_send_ldap_result(pb, rc, NULL, NULL, 0, NULL);
		slapi_log_error(SLAPI_LOG_PLUGIN, "addrdnvalues_preop_add", "%s\n", ldap_err2string(rc));
		return -1;
	}

	if (dn[0] != NULL) {
		LDAPRDN rdn = dn[0];

		for (i = 0; rdn[i] != NULL; i++) {
			LDAPAVA *ava = &rdn[0][i];
			struct berval *vals[2];
			Slapi_Attr *a = NULL;

			/* 0 means attr exists */
			if (slapi_entry_attr_find(e, ava->la_attr.bv_val, &a) == 0 &&
			    a != NULL &&
			    slapi_attr_value_find(a, &ava->la_value) == 0)
			{
				/* RDN in entry */
				continue;
			} /* else RDN not in entry */

			vals[0] = &ava->la_value;
			vals[1] = NULL;

			slapi_entry_attr_merge(e, ava->la_attr.bv_val, vals);
		}
	}

	ldap_dnfree(dn);

	return 0;
}

int addrdnvalues_preop_init(Slapi_PBlock *pb)
{
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03) != 0 ||
	    slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &pluginDescription) != 0 ||
	    slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN, (void *)addrdnvalues_preop_add) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, "addrdnvalues_preop_init",
				"Error registering %s\n", pluginDescription.spd_description);
		return -1;
	}

	return 0;
}


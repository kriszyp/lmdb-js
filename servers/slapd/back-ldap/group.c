/* group.c - ldap backend acl group routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"


/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
int
ldap_back_group(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
	ObjectClass* group_oc,
	AttributeDescription* group_at
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;    
	int rc = 1;
	Attribute   *attr;
	Entry *e;
	struct berval bv;
	LDAPMessage	*result;
	char *gattr[2];
	char *filter;
	LDAP *ld;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	const char *group_oc_name = NULL;
	const char *group_at_name = group_at->ad_cname->bv_val;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name = group_oc->soc_names[0];
	} else {
		group_oc_name = group_oc->soc_oid;
	}

	if (target != NULL && strcmp(target->e_ndn, gr_ndn) == 0) {
		/* we already have a copy of the entry */
		e = target;

		if( is_entry_objectclass( e, group_oc ) ) {
			return(1);
		}

		if ((attr = attr_find(e->e_attrs, group_at)) == NULL)
			return(1);

		bv.bv_val = (char *) op_ndn;
		bv.bv_len = strlen( op_ndn );         
		if( value_find( group_at, attr->a_vals, &bv ) == 0  )
			return(1);

	} else {
		filter = ch_malloc(sizeof("(&(objectclass=)(=))")
							+ strlen(group_oc_name)
							+ strlen(group_at_name)
							+ strlen(op_ndn) + 1);
		if (filter == NULL)
			return(1);

		if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
			ch_free(filter);
			return(1);
		}

		if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE) == LDAP_SUCCESS) {
			strcpy(filter, "(&(objectclass=");
			strcat(filter, group_oc_name);
			strcat(filter, ")(");
			strcat(filter, group_at_name);
			strcat(filter, "=");
			strcat(filter, op_ndn);
			strcat(filter, "))");

			gattr[0] = "objectclass";
			gattr[1] = NULL;
			if (ldap_search_ext_s(ld, gr_ndn, LDAP_SCOPE_BASE, filter,
									gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
									LDAP_NO_LIMIT, &result) == LDAP_SUCCESS)
			{
				if (ldap_first_entry(ld, result) != NULL)
					rc = 0;
				ldap_msgfree(result);
			}
		}
		ldap_unbind(ld);
		ch_free(filter);
		return(rc);
    }

	return(0);
}


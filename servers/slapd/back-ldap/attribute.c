/* group.c - ldap backend acl group routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"


/* return 0 IFF we can retrieve the attributes
 * of entry with ndn
 */
int
ldap_back_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	struct berval	*ndn,
	AttributeDescription *entry_at,
	BerVarray *vals
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;    
	int rc = 1, i, j, count, is_oc;
	Attribute *attr = NULL;
	BerVarray abv, v;
	struct berval mapped = { 0, NULL };
	char **vs = NULL;
	LDAPMessage	*result = NULL, *e = NULL;
	char *gattr[2];
	LDAP *ld = NULL;

	*vals = NULL;
	if (target != NULL && dn_match( &target->e_nname, ndn )) {
		/* we already have a copy of the entry */
		/* attribute and objectclass mapping has already been done */
		if ((attr = attr_find(target->e_attrs, entry_at)) == NULL)
			return(1);

		for ( count = 0; attr->a_vals[count].bv_val != NULL; count++ ) { }
		v = (BerVarray) ch_calloc( (count + 1), sizeof(struct berval) );
		if (v != NULL) {
			for ( j = 0, abv = attr->a_vals; --count >= 0; abv++ ) {
				if ( abv->bv_len > 0 ) {
					ber_dupbv( &v[j], abv );
					if( v[j].bv_val == NULL )
						break;
				}
			}
			v[j].bv_val = NULL;
			*vals = v;
			return 0;
		}

	}
	ldap_back_map(&li->at_map, &entry_at->ad_cname, &mapped, BACKLDAP_MAP);
	if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
		return 1;
	}

	if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
		return 1;
	}

	if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
		goto cleanup;
	}

	gattr[0] = mapped.bv_val;
	gattr[1] = NULL;
	if (ldap_search_ext_s(ld, ndn->bv_val, LDAP_SCOPE_BASE, "(objectclass=*)",
				gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
				LDAP_NO_LIMIT, &result) != LDAP_SUCCESS)
	{
		goto cleanup;
	}

	if ((e = ldap_first_entry(ld, result)) == NULL) {
		goto cleanup;
	}
		
	vs = ldap_get_values(ld, e, mapped.bv_val);
	if (vs == NULL) {
		goto cleanup;
	}

	for ( count = 0; vs[count] != NULL; count++ ) { }
	v = (BerVarray) ch_calloc( (count + 1), sizeof(struct berval) );
	if (v == NULL) {
		goto cleanup;
	}

	is_oc = (strcasecmp("objectclass", mapped.bv_val) == 0);
	for ( i = 0, j = 0; i < count; i++) {
		ber_str2bv(vs[i], 0, 0, &v[j] );
		if (!is_oc) {
			if( v[j].bv_val == NULL )
				ch_free(vs[i]);
			else
				j++;
		} else {
			ldap_back_map(&li->oc_map, &v[j], &mapped,
					BACKLDAP_REMAP);
			if (mapped.bv_val && mapped.bv_val[0] != '\0') {
				ber_dupbv( &v[j], &mapped );
				if (v[j].bv_val)
					j++;
			}
			ch_free(vs[i]);
		}
	}
	v[j].bv_val = NULL;
	*vals = v;
	rc = 0;
	ch_free(vs);
	vs = NULL;

cleanup:
	if (vs) {
		ldap_value_free(vs);
	}
	if (result) {
		ldap_msgfree(result);
	}
	ldap_unbind(ld);

	return(rc);
}


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


/* return 0 IFF we can retrieve the attributes
 * of entry with ndn
 */
int
ldap_back_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	const char	*ndn,
	AttributeDescription *entry_at,
	struct berval ***vals
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;    
	int rc = 1, i, j, count, is_oc;
	Attribute *attr;
	struct berval **abv, **v;
	char **vs, *mapped;
	LDAPMessage	*result, *e;
	char *gattr[2];
	LDAP *ld;

	*vals = NULL;
	if (target != NULL && strcmp(target->e_ndn, ndn) == 0) {
		/* we already have a copy of the entry */
		/* attribute and objectclass mapping has already been done */
		if ((attr = attr_find(target->e_attrs, entry_at)) == NULL)
			return(1);

		for ( count = 0; attr->a_vals[count] != NULL; count++ ) { }
		v = (struct berval **) ch_calloc( (count + 1), sizeof(struct berval *) );
		if (v != NULL) {
			for ( j = 0, abv = attr->a_vals; --count >= 0; abv++ ) {
				if ( (*abv)->bv_len > 0 ) {
					v[j] = ber_bvdup( *abv );
					if( v[j] == NULL )
						break;
				}
			}
			v[j] = NULL;
			*vals = v;
			rc = 0;
		}

	} else {
		mapped = ldap_back_map(&li->at_map, entry_at->ad_cname.bv_val, 0);
		if (mapped == NULL)
			return(1);

		if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
			return(1);
		}

		if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE) == LDAP_SUCCESS) {
			gattr[0] = mapped;
			gattr[1] = NULL;
			if (ldap_search_ext_s(ld, ndn, LDAP_SCOPE_BASE, "(objectclass=*)",
									gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
									LDAP_NO_LIMIT, &result) == LDAP_SUCCESS)
			{
				if ((e = ldap_first_entry(ld, result)) != NULL) {
					vs = ldap_get_values(ld, e, mapped);
					if (vs != NULL) {
						for ( count = 0; vs[count] != NULL; count++ ) { }
						v = (struct berval **) ch_calloc( (count + 1), sizeof(struct berval *) );
						if (v == NULL) {
							ldap_value_free(vs);
						} else {
							is_oc = (strcasecmp("objectclass", mapped) == 0);
							for ( i = 0, j = 0; i < count; i++) {
								if (!is_oc) {
									v[j] = ber_bvstr( vs[i] );
									if( v[j] == NULL )
										ch_free(vs[i]);
									else
										j++;
								} else {
									mapped = ldap_back_map(&li->oc_map, vs[i], 1);
									if (mapped) {
										mapped = ch_strdup( mapped );
										if (mapped) {
											v[j] = ber_bvstr( mapped );
											if (v[j])
												j++;
										}
									}
									ch_free(vs[i]);
								}
							}
							v[j] = NULL;
							*vals = v;
							rc = 0;
							ch_free(vs);
						}
					}
				}
				ldap_msgfree(result);
			}
		}
		ldap_unbind(ld);
    }

	return(rc);
}


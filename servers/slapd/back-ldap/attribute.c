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
 * of entry with e_ndn
 */
int
ldap_back_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	const char	*e_ndn,
	AttributeDescription *entry_at,
	const char ***vals
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;    
	int rc = 1, i, j;
	Attribute *attr;
	struct berval **abv;
	char *s, **v;
	LDAPMessage	*result, *e;
	char *gattr[2];
	LDAP *ld;

	*vals = NULL;
	if (target != NULL && strcmp(target->e_ndn, e_ndn) == 0) {
		/* we already have a copy of the entry */
		if ((attr = attr_find(target->e_attrs, entry_at)) == NULL)
			return(1);

		for ( i = 0; attr->a_vals[i] != NULL; i++ ) { }
		v = (char **) ch_calloc( (i + 1), sizeof(char *) );
		if (v != NULL) {
			for ( j = 0, abv = attr->a_vals; --i >= 0; abv++ ) {
				if ( (*abv)->bv_len > 0 ) {
					s = ch_malloc( (*abv)->bv_len + 1 );
					if( s == NULL )
						break;
					memcpy(s, (*abv)->bv_val, (*abv)->bv_len);
					s[(*abv)->bv_len] = 0;
					v[j++] = s;
				}
			}
			v[j] = NULL;
			*vals = v;
			rc = 0;
		}

	} else {
		if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
			return(1);
		}

		if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE) == LDAP_SUCCESS) {
			gattr[0] = entry_at->ad_cname->bv_val;
			gattr[1] = NULL;
			if (ldap_search_ext_s(ld, e_ndn, LDAP_SCOPE_BASE, "(objectclass=*)",
									gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
									LDAP_NO_LIMIT, &result) == LDAP_SUCCESS)
			{
				if ((e = ldap_first_entry(ld, result)) != NULL) {
					*vals = ldap_get_values(ld, e, entry_at->ad_cname->bv_val);
					if (*vals != NULL)
						rc = 0;
				}
				ldap_msgfree(result);
			}
		}
		ldap_unbind(ld);
    }

	return(rc);
}


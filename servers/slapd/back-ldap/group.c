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
#include "lutil.h"

/* return 0 IFF op_dn is a value in group_at (member) attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of group_oc (groupOfNames)
 */
int
ldap_back_group(
	Backend		*be,
	Connection 	*conn,
	Operation 	*op,
	Entry		*target,
	struct berval	*gr_ndn,
	struct berval	*op_ndn,
	ObjectClass	*group_oc,
	AttributeDescription* group_at
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;    
	int rc = 1;
	Attribute   *attr;

	LDAPMessage	*result;
	char *gattr[2];
	char *filter = NULL, *ptr;
	LDAP *ld;
	struct berval mop_ndn = { 0, NULL }, mgr_ndn = { 0, NULL };

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	struct berval group_oc_name = {0, NULL};
	struct berval group_at_name = group_at->ad_cname;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name.bv_val = group_oc->soc_names[0];
	} else {
		group_oc_name.bv_val = group_oc->soc_oid;
	}
	if (group_oc_name.bv_val)
		group_oc_name.bv_len = strlen(group_oc_name.bv_val);

	if (target != NULL && dn_match( &target->e_nname, gr_ndn ) ) {
		/* we already have a copy of the entry */
		/* attribute and objectclass mapping has already been done */

		/*
		 * first we need to check if the objectClass attribute
		 * has been retieved; otherwise we need to repeat the search
		 */
		attr = attr_find( target->e_attrs, ad_objectClass );
		if ( attr != NULL ) {

			/*
			 * Now we can check for the group objectClass value
			 */
			if( !is_entry_objectclass( target, group_oc, 0 ) ) {
				return(1);
			}

			/*
			 * This part has been reworked: the group attr compare
			 * fails only if the attribute is PRESENT but the value
			 * is NOT PRESENT; if the attribute is NOT PRESENT, the
			 * search must be repeated as well.
			 * This may happen if a search for an entry has already
			 * been performed (target is not null) but the group
			 * attribute has not been required
			 */
			if ((attr = attr_find(target->e_attrs, group_at)) != NULL) {
				if( value_find_ex( group_at, SLAP_MR_VALUE_NORMALIZED_MATCH,
					attr->a_vals, op_ndn ) != LDAP_SUCCESS )
					return(1);
				return(0);
			} /* else: repeat the search */
		} /* else: repeat the search */
	} /* else: do the search */

	/*
	 * Rewrite the op ndn if needed
	 */
#ifdef ENABLE_REWRITE
	switch ( rewrite_session( li->rwinfo, "bindDn",
				op_ndn->bv_val, conn, &mop_ndn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mop_ndn.bv_val == NULL ) {
			mop_ndn = *op_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] bindDn (op ndn in group): \"%s\" -> \"%s\"\n", 
			op_ndn->bv_val, mop_ndn.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> bindDn (op ndn in group): \"%s\" -> \"%s\"\n%s",
			op_ndn->bv_val, mop_ndn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
	
	case REWRITE_REGEXEC_UNWILLING:
	
	case REWRITE_REGEXEC_ERR:
		goto cleanup;
	}

	/*
	 * Rewrite the gr ndn if needed
	 */
        switch ( rewrite_session( li->rwinfo, "searchBase",
				gr_ndn->bv_val, conn, &mgr_ndn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mgr_ndn.bv_val == NULL ) {
			mgr_ndn = *gr_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] searchBase (gr ndn in group): \"%s\" -> \"%s\"\n%s", 
			gr_ndn->bv_val, mgr_ndn.bv_val, "" );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> searchBase (gr ndn in group):"
			" \"%s\" -> \"%s\"\n%s",
			gr_ndn->bv_val, mgr_ndn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
	
	case REWRITE_REGEXEC_UNWILLING:
	
	case REWRITE_REGEXEC_ERR:
		goto cleanup;
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, op_ndn, &mop_ndn, 1, 1 );
	if ( mop_ndn.bv_val == NULL ) {
		goto cleanup;
	}
	ldap_back_dn_massage( li, gr_ndn, &mgr_ndn, 1, 1 );
	if ( mgr_ndn.bv_val == NULL ) {
		goto cleanup;
	}
#endif /* !ENABLE_REWRITE */

	ldap_back_map(&li->oc_map, &group_oc_name, &group_oc_name,
			BACKLDAP_MAP);
	if (group_oc_name.bv_val == NULL || group_oc_name.bv_val[0] == '\0')
		goto cleanup;
	ldap_back_map(&li->at_map, &group_at_name, &group_at_name,
			BACKLDAP_MAP);
	if (group_at_name.bv_val == NULL || group_at_name.bv_val[0] == '\0')
		goto cleanup;

	filter = ch_malloc(sizeof("(&(objectclass=)(=))")
						+ group_oc_name.bv_len
						+ group_at_name.bv_len
						+ mop_ndn.bv_len + 1);
	if (filter == NULL)
		goto cleanup;

	if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
		goto cleanup;
	}

	if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE)
			!= LDAP_SUCCESS) {
		goto cleanup;
	}

	ptr = lutil_strcopy(filter, "(&(objectclass=");
	ptr = lutil_strcopy(ptr, group_oc_name.bv_val);
	ptr = lutil_strcopy(ptr, ")(");
	ptr = lutil_strcopy(ptr, group_at_name.bv_val);
	ptr = lutil_strcopy(ptr, "=");
	ptr = lutil_strcopy(ptr, mop_ndn.bv_val);
	strcpy(ptr, "))");

	gattr[0] = "objectclass";
	gattr[1] = NULL;
	if (ldap_search_ext_s(ld, mgr_ndn.bv_val, LDAP_SCOPE_BASE, filter,
		gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
		LDAP_NO_LIMIT, &result) == LDAP_SUCCESS) {
		if (ldap_first_entry(ld, result) != NULL)
			rc = 0;
		ldap_msgfree(result);
	}

cleanup:;
	if ( ld != NULL ) {
		ldap_unbind(ld);
	}
	ch_free(filter);
	if ( mop_ndn.bv_val != op_ndn->bv_val ) {
		free( mop_ndn.bv_val );
	}
	if ( mgr_ndn.bv_val != gr_ndn->bv_val ) {
		free( mgr_ndn.bv_val );
	}
	return(rc);
}

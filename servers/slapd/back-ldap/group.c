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


/* return 0 IFF op_dn is a value in group_at (member) attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of group_oc (groupOfNames)
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
	struct berval bv;

	LDAPMessage	*result;
	char *gattr[2];
	char *filter;
	LDAP *ld;
	char *mop_ndn, *mgr_ndn;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	char *group_oc_name = NULL;
	char *group_at_name = group_at->ad_cname.bv_val;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name = group_oc->soc_names[0];
	} else {
		group_oc_name = group_oc->soc_oid;
	}

	if (target != NULL && strcmp(target->e_ndn, gr_ndn) == 0) {
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
			if( !is_entry_objectclass( target, group_oc ) ) {
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
				bv.bv_val = (char *) op_ndn;
				bv.bv_len = strlen( op_ndn );         
				if( value_find( group_at, attr->a_vals, &bv ) != LDAP_SUCCESS  )
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
				op_ndn, conn, &mop_ndn ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mop_ndn == NULL ) {
			mop_ndn = ( char * )op_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] bindDn (op ndn in group):"
				" \"%s\" -> \"%s\"\n", op_ndn, mop_ndn ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> bindDn (op ndn in group): \"%s\" -> \"%s\"\n%s",
			op_ndn, mop_ndn, "" );
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
				gr_ndn, conn, &mgr_ndn ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mgr_ndn == NULL ) {
			mgr_ndn = ( char * )gr_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] searchBase (gr ndn in group):"
				" \"%s\" -> \"%s\"\n%s", gr_ndn, mgr_ndn ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"rw> searchBase (gr ndn in group):"
			" \"%s\" -> \"%s\"\n%s",
			gr_ndn, mgr_ndn, "" );
#endif /* !NEW_LOGGING */
		break;
	
	case REWRITE_REGEXEC_UNWILLING:
	
	case REWRITE_REGEXEC_ERR:
		goto cleanup;
	}
#else /* !ENABLE_REWRITE */
	mop_ndn = ldap_back_dn_massage( li, ch_strdup( op_ndn ), 1 );
	if ( mop_ndn == NULL ) {
		goto cleanup;
	}
	mgr_ndn = ldap_back_dn_massage( li, ch_strdup( gr_ndn ), 1 );
	if ( mgr_ndn == NULL ) {
		goto cleanup;
	}
#endif /* !ENABLE_REWRITE */

	group_oc_name = ldap_back_map(&li->oc_map, group_oc_name, 0);
	if (group_oc_name == NULL)
		goto cleanup;
	group_at_name = ldap_back_map(&li->at_map, group_at_name, 0);
	if (group_at_name == NULL)
		goto cleanup;

	filter = ch_malloc(sizeof("(&(objectclass=)(=))")
						+ strlen(group_oc_name)
						+ strlen(group_at_name)
						+ strlen(mop_ndn) + 1);
	if (filter == NULL)
		goto cleanup;

	if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
		goto cleanup;
	}

	if (ldap_bind_s(ld, li->binddn, li->bindpw, LDAP_AUTH_SIMPLE)
			!= LDAP_SUCCESS) {
		goto cleanup;
	}

	strcpy(filter, "(&(objectclass=");
	strcat(filter, group_oc_name);
	strcat(filter, ")(");
	strcat(filter, group_at_name);
	strcat(filter, "=");
	strcat(filter, mop_ndn);
	strcat(filter, "))");

	gattr[0] = "objectclass";
	gattr[1] = NULL;
	if (ldap_search_ext_s(ld, mgr_ndn, LDAP_SCOPE_BASE, filter,
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
#ifdef ENABLE_REWRITE
	if ( mop_ndn != op_ndn ) {
#endif /* ENABLE_REWRITE */
		free( mop_ndn );
#ifdef ENABLE_REWRITE
	}
	if ( mgr_ndn != gr_ndn ) {
#endif /* ENABLE_REWRITE */
		free( mgr_ndn );
#ifdef ENABLE_REWRITE
	}
#endif /* ENABLE_REWRITE */
	return(rc);
}


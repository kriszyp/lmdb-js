/* group.c - ldbm backend acl group routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
int
ldbm_back_group(
	Backend	*be,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	ObjectClass *group_oc,
	AttributeDescription *group_at
#else
	const char	*group_oc,
	const char	*group_at
#endif
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry        *e;
	int          rc = 1;
	Attribute   *attr;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	const char *group_oc_name = NULL;
	const char *group_at_name = group_at->ad_cname->bv_val;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name = group_oc->soc_names[0];
	} else {
		group_oc_name = group_oc->soc_oid;
	}
#else
	struct berval bv;
	const char *ad_objectClass = "objectclass";
	const char *group_oc_name = group_oc;
	const char *group_at_name = group_at;
#endif

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: gr dn: \"%s\"\n",
		gr_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: op dn: \"%s\"\n",
		op_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: oc: \"%s\" at: \"%s\"\n", 
		group_oc_name, group_at_name, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: tr dn: \"%s\"\n",
		target->e_ndn, 0, 0 ); 

	if (strcmp(target->e_ndn, gr_ndn) == 0) {
		/* we already have a LOCKED copy of the entry */
		e = target;
        	Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_group: target is group: \"%s\"\n",
			gr_ndn, 0, 0 );

	} else {
		/* can we find group entry with reader lock */
		if ((e = dn2entry_r(be, gr_ndn, NULL )) == NULL) {
			Debug( LDAP_DEBUG_ACL,
				"=> ldbm_back_group: cannot find group: \"%s\"\n",
					gr_ndn, 0, 0 ); 
			return( 1 );
		}
		
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_group: found group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
    }

	/* find it's objectClass and member attribute values
	 * make sure this is a group entry
	 * finally test if we can find op_dn in the member attribute value list *
	 */
        
	rc = 1;
        
	if ((attr = attr_find(e->e_attrs, ad_objectClass)) == NULL)  {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find objectClass\n", 0, 0, 0 );
		goto return_results;
	}
	
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else

	bv.bv_val = "ALIAS";
	bv.bv_len = sizeof("ALIAS")-1;

	if ( value_find(attr->a_vals, &bv, attr->a_syntax, 1) == 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is an alias\n", 0, 0, 0 );
		goto return_results;
	}

	bv.bv_val = "REFERRAL";
	bv.bv_len = sizeof("REFERRAL")-1;

	if ( value_find(attr->a_vals, &bv, attr->a_syntax, 1) == 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is a referral\n",
			0, 0, 0 );
		goto return_results;
	}

	bv.bv_val = (char *) group_oc_name;
	bv.bv_len = strlen( bv.bv_val );         

	if (value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s in objectClass\n", 
				group_oc_name, 0, 0 ); 
		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, group_at)) == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s\n",
			group_at_name, 0, 0 ); 
		goto return_results;
	}

	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: found objectClass %s and %s\n",
		group_oc_name, group_at_name, 0 ); 

	bv.bv_val = (char *) op_ndn;
	bv.bv_len = strlen( op_ndn );         

	if( value_find( attr->a_vals, &bv, attr->a_syntax, 1) != 0 )
	{
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: \"%s\" not in \"%s\": %s\n", 
			op_ndn, gr_ndn, group_at_name ); 
		goto return_results;
	}
#endif

	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: \"%s\" is in \"%s\": %s\n", 
		op_ndn, gr_ndn, group_at_name ); 

	rc = 0;

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );                 
	}

	Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: rc=%d\n", rc, 0, 0 ); 
	return(rc);
}


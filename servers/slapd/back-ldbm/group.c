/* group.c - ldbm backend acl group routine */
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
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
int
ldbm_back_group(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	struct berval	*gr_ndn,
	struct berval	*op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry	     *e;
	int	     rc = 1;
	Attribute   *attr;

	const char *group_oc_name = NULL;
	const char *group_at_name = group_at->ad_cname.bv_val;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name = group_oc->soc_names[0];
	} else {
		group_oc_name = group_oc->soc_oid;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		"ldbm_back_group: check (%s) member of (%s), oc %s\n",
		op_ndn->bv_val, gr_ndn->bv_val, group_oc_name );
#else
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: gr dn: \"%s\"\n",
		gr_ndn->bv_val, 0, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: op dn: \"%s\"\n",
		op_ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: oc: \"%s\" at: \"%s\"\n", 
		group_oc_name, group_at_name, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_group: tr dn: \"%s\"\n",
		target->e_ndn, 0, 0 ); 
#endif

	if (dn_match(&target->e_nname, gr_ndn)) {
		/* we already have a LOCKED copy of the entry */
		e = target;
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_group: target is group (%s)\n", gr_ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_group: target is group: \"%s\"\n",
			gr_ndn->bv_val, 0, 0 );
#endif


	} else {
		/* can we find group entry with reader lock */
		if ((e = dn2entry_r(be, gr_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1, 
				"ldbm_back_group: cannot find group (%s)\n", 
				gr_ndn->bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_ACL,
				"=> ldbm_back_group: cannot find group: \"%s\"\n",
				gr_ndn->bv_val, 0, 0 ); 
#endif

			return( 1 );
		}
		
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_group: found group (%s)\n", gr_ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_group: found group: \"%s\"\n",
			gr_ndn->bv_val, 0, 0 ); 
#endif

    }

	/* find it's objectClass and member attribute values
	 * make sure this is a group entry
	 * finally test if we can find op_dn in the member attribute value list *
	 */
	
	rc = 1;
	
	
	if( is_entry_alias( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_group: group (%s) is an alias\n", gr_ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is an alias\n", 0, 0, 0 );
#endif

		goto return_results;
	}

	if( is_entry_referral( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_group: group (%s) is a referral.\n", gr_ndn->bv_val,0,0);
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is an referral\n", 0, 0, 0 );
#endif

		goto return_results;
	}

	if( !is_entry_objectclass( e, group_oc, 0 ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_group: failed to find %s in objectClass.\n",
			group_oc_name, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s in objectClass\n", 
				group_oc_name, 0, 0 ); 
#endif

		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, group_at)) == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_group: failed to find %s\n", group_at_name, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s\n",
			group_at_name, 0, 0 ); 
#endif

		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		   "ldbm_back_group: found objectClass %s and %s\n",
		   group_oc_name, group_at_name, 0 );
#else
	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: found objectClass %s and %s\n",
		group_oc_name, group_at_name, 0 ); 
#endif


	if( value_find_ex( group_at, SLAP_MR_VALUE_NORMALIZED_MATCH,
		attr->a_vals, op_ndn ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_group: \"%s\" not in \"%s\": %s\n",
			op_ndn->bv_val, gr_ndn->bv_val, group_at_name );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: \"%s\" not in \"%s\": %s\n", 
			op_ndn->bv_val, gr_ndn->bv_val, group_at_name ); 
#endif

		goto return_results;
	}


#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, 
		"ldbm_back_group: %s is in %s: %s\n",
		op_ndn->bv_val, gr_ndn->bv_val, group_at_name );
#else
	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: \"%s\" is in \"%s\": %s\n", 
		op_ndn->bv_val, gr_ndn->bv_val, group_at_name ); 
#endif


	rc = 0;

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );		  
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_group: rc=%d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: rc=%d\n", rc, 0, 0 ); 
#endif

	return(rc);
}


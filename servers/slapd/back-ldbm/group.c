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
	Connection *conn,
	Operation *op,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry	     *e;
	int	     rc = 1;
	Attribute   *attr;
	struct berval bv;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	const char *group_oc_name = NULL;
	const char *group_at_name = group_at->ad_cname->bv_val;

	if( group_oc->soc_names && group_oc->soc_names[0] ) {
		group_oc_name = group_oc->soc_names[0];
	} else {
		group_oc_name = group_oc->soc_oid;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_group: check (%s) member of (%s), oc %s\n",
		   op_ndn, gr_ndn, group_oc_name ));
#else
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
#endif

	if (strcmp(target->e_ndn, gr_ndn) == 0) {
		/* we already have a LOCKED copy of the entry */
		e = target;
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_group: target is group (%s)\n", gr_ndn ));
#else
		Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_group: target is group: \"%s\"\n",
			gr_ndn, 0, 0 );
#endif


	} else {
		/* can we find group entry with reader lock */
		if ((e = dn2entry_r(be, gr_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_back_group: cannot find group (%s)\n",
				   gr_ndn ));
#else
			Debug( LDAP_DEBUG_ACL,
				"=> ldbm_back_group: cannot find group: \"%s\"\n",
					gr_ndn, 0, 0 ); 
#endif

			return( 1 );
		}
		
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_group: found group (%s)\n", gr_ndn ));
#else
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_group: found group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
#endif

    }

	/* find it's objectClass and member attribute values
	 * make sure this is a group entry
	 * finally test if we can find op_dn in the member attribute value list *
	 */
	
	rc = 1;
	
	
	if( is_entry_alias( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_group: group (%s) is an alias\n", gr_ndn ));
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is an alias\n", 0, 0, 0 );
#endif

		goto return_results;
	}

	if( is_entry_referral( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_group: group (%s) is a referral.\n", gr_ndn ));
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: group is an referral\n", 0, 0, 0 );
#endif

		goto return_results;
	}

	if( !is_entry_objectclass( e, group_oc ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "ldbm_back_group: failed to find %s in objectClass.\n",
			   group_oc_name ));
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s in objectClass\n", 
				group_oc_name, 0, 0 ); 
#endif

		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, group_at)) == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_group: failed to find %s\n", group_at_name ));
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: failed to find %s\n",
			group_at_name, 0, 0 ); 
#endif

		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_group: found objectClass %s and %s\n",
		   group_oc_name, group_at_name ));
#else
	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: found objectClass %s and %s\n",
		group_oc_name, group_at_name, 0 ); 
#endif


	bv.bv_val = (char *) op_ndn;
	bv.bv_len = strlen( op_ndn );	      

	if( value_find( group_at, attr->a_vals, &bv ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "ldbm_back_group: \"%s\" not in \"%s\": %s\n",
			   op_ndn, gr_ndn, group_at_name ));
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_group: \"%s\" not in \"%s\": %s\n", 
			op_ndn, gr_ndn, group_at_name ); 
#endif

		goto return_results;
	}



#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
		   "ldbm_back_group: %s is in %s: %s\n",
		   op_ndn, gr_ndn, group_at_name ));
#else
	Debug( LDAP_DEBUG_ACL,
		"<= ldbm_back_group: \"%s\" is in \"%s\": %s\n", 
		op_ndn, gr_ndn, group_at_name ); 
#endif


	rc = 0;

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );		  
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_group: rc=%d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: rc=%d\n", rc, 0, 0 ); 
#endif

	return(rc);
}


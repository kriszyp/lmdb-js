/* attribute.c - ldbm backend acl attribute routine */
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

/* return LDAP_SUCCESS IFF we can retrieve the attributes
 * of entry with e_ndn
 */
int
ldbm_back_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	struct berval	*entry_ndn,
	AttributeDescription *entry_at,
	BerVarray *vals )
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry	     *e;
	int	     rc;
	Attribute   *attr;
	BerVarray v;
	const char *entry_at_name = entry_at->ad_cname.bv_val;
	struct berval *iv, *jv;
	AccessControlState acl_state = ACL_STATE_INIT;
	int nvals = 0;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ARGS,
		"ldbm_back_attribute: gr dn: \"%s\"\n", entry_ndn->bv_val, 0, 0 );
	LDAP_LOG( BACK_LDBM, ARGS, 
		"ldbm_back_attribute: at: \"%s\"\n", entry_at_name, 0, 0);
	LDAP_LOG( BACK_LDBM, ARGS, "ldbm_back_attribute: tr dn: \"%s\"\n",
		target ? target->e_ndn : "", 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: gr dn: \"%s\"\n",
		entry_ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: at: \"%s\"\n", 
		entry_at_name, 0, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: tr dn: \"%s\"\n",
		target ? target->e_ndn : "", 0, 0 ); 
#endif

	if (target != NULL && dn_match( &target->e_nname, entry_ndn) ) {
		/* we already have a LOCKED copy of the entry */
		e = target;
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_attribute: target is LOCKED (%s)\n", 
			entry_ndn->bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_attribute: target is entry: \"%s\"\n",
			entry_ndn->bv_val, 0, 0 );
#endif


	} else {
		/* can we find entry with reader lock */
		if ((e = dn2entry_r(be, entry_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_back_attribute: cannot find entry (%s)\n",
				entry_ndn->bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_ACL,
				"=> ldbm_back_attribute: cannot find entry: \"%s\"\n",
					entry_ndn->bv_val, 0, 0 ); 
#endif

			return LDAP_NO_SUCH_OBJECT; 
		}
		
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_attribute: found entry (%s)\n", entry_ndn->bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_attribute: found entry: \"%s\"\n",
			entry_ndn->bv_val, 0, 0 ); 
#endif

    }

	/* find attribute values */

	if( is_entry_alias( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_attribute: entry (%s) is an alias\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: entry is an alias\n", 0, 0, 0 );
#endif

		rc = LDAP_ALIAS_PROBLEM;
		goto return_results;
	}

	if( is_entry_referral( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_attribute: entry (%s) is a referral.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: entry is an referral\n", 0, 0, 0 );
#endif

		rc = LDAP_REFERRAL;
		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, entry_at)) == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_attribute: failed to find %s.\n", entry_at_name, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: failed to find %s\n",
			entry_at_name, 0, 0 ); 
#endif

		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

	if (conn != NULL && op != NULL
		&& access_allowed( be, conn, op, e, entry_at, NULL,
			ACL_AUTH, &acl_state ) == 0)
	{
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto return_results;
	}

	for ( iv = attr->a_vals; iv->bv_val != NULL; iv++ ) {
		/* count them */
	}

	v = (BerVarray) ch_malloc( sizeof(struct berval) * ((iv - attr->a_vals)+1) );

	for ( iv=attr->a_vals, jv=v; iv->bv_val; iv++ ) {
		if( conn != NULL
			&& op != NULL
			&& access_allowed( be, conn, op, e, entry_at,
				iv, ACL_AUTH, &acl_state ) == 0)
		{
			continue;
		}
		ber_dupbv( jv, iv );

		if( jv->bv_val != NULL ) jv++;
	}

	nvals = jv - v;

	if( jv == v ) {
		ch_free( v );
		*vals = NULL;
		rc = LDAP_INSUFFICIENT_ACCESS;
	} else {
		jv->bv_val = NULL;
		*vals = v;
		rc = LDAP_SUCCESS;
	}

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );		  
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		"ldbm_back_attribute: rc=%d nvals=%d.\n", rc, nvals, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldbm_back_attribute: rc=%d nvals=%d\n",
		rc, nvals, 0 ); 
#endif

	return(rc);
}


/* attribute.c - ldbm backend acl attribute routine */
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


/* return 0 IFF we can retrieve the attributes
 * of entry with e_ndn
 */
int
ldbm_back_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	const char	*e_ndn,
	AttributeDescription *entry_at,
	const char ***vals
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry        *e;
	int          i, j, rc = 1;
	Attribute   *attr;
	struct berval **abv;
	char *s, **v;
	const char *entry_at_name = entry_at->ad_cname->bv_val;

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: gr dn: \"%s\"\n",
		e_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: at: \"%s\"\n", 
		entry_at_name, 0, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_attribute: tr dn: \"%s\"\n",
		target ? target->e_ndn : "", 0, 0 ); 

	if (target != NULL && strcmp(target->e_ndn, e_ndn) == 0) {
		/* we already have a LOCKED copy of the entry */
		e = target;
        	Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_attribute: target is entry: \"%s\"\n",
			e_ndn, 0, 0 );

	} else {
		/* can we find entry with reader lock */
		if ((e = dn2entry_r(be, e_ndn, NULL )) == NULL) {
			Debug( LDAP_DEBUG_ACL,
				"=> ldbm_back_attribute: cannot find entry: \"%s\"\n",
					e_ndn, 0, 0 ); 
			return( 1 );
		}
		
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_attribute: found entry: \"%s\"\n",
			e_ndn, 0, 0 ); 
    }

	rc = 1;

	/* find attribute values
	 */
        
	if( is_entry_alias( e ) ) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: entry is an alias\n", 0, 0, 0 );
		goto return_results;
	}

	if( is_entry_referral( e ) ) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: entry is an referral\n", 0, 0, 0 );
		goto return_results;
	}

	if (conn != NULL && op != NULL
		&& access_allowed(be, conn, op, e, slap_schema.si_ad_entry, NULL, ACL_SEARCH) == 0)
	{
		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, entry_at)) == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_attribute: failed to find %s\n",
			entry_at_name, 0, 0 ); 
		goto return_results;
	}

	if (conn != NULL && op != NULL
		&& access_allowed(be, conn, op, e, entry_at, NULL, ACL_SEARCH) == 0)
	{
		goto return_results;
	}

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
	}

	rc = 0;

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );                 
	}

	Debug( LDAP_DEBUG_TRACE, "ldbm_back_attribute: rc=%d\n", rc, 0, 0 ); 
	return(rc);
}


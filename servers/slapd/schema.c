/* schema.c - routines to manage schema definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"


#if defined( SLAPD_SCHEMA_DN )

int
schema_info( Entry **entry, const char **text )
{
	AttributeDescription *ad_structuralObjectClass
		= slap_schema.si_ad_structuralObjectClass;
	AttributeDescription *ad_objectClass
		= slap_schema.si_ad_objectClass;

	Entry		*e;
	struct berval	vals[2];

	vals[1].bv_val = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	ber_str2bv( SLAPD_SCHEMA_DN, sizeof(SLAPD_SCHEMA_DN)-1, 1, &e->e_name);
	(void) dnNormalize2( NULL, &e->e_name, &e->e_nname );
	e->e_private = NULL;

	vals[0].bv_val = "LDAPsubentry";
	vals[0].bv_len = sizeof("LDAPsubentry")-1;
	attr_merge( e, ad_structuralObjectClass, vals );

	vals[0].bv_val = "top";
	vals[0].bv_len = sizeof("top")-1;
	attr_merge( e, ad_objectClass, vals );

	vals[0].bv_val = "LDAPsubentry";
	vals[0].bv_len = sizeof("LDAPsubentry")-1;
	attr_merge( e, ad_objectClass, vals );

	vals[0].bv_val = "subschema";
	vals[0].bv_len = sizeof("subschema")-1;
	attr_merge( e, ad_objectClass, vals );

	vals[0].bv_val = "extensibleObject";
	vals[0].bv_len = sizeof("extensibleObject")-1;
	attr_merge( e, ad_objectClass, vals );

	{
		int rc;
		AttributeDescription *desc = NULL;
		struct berval rdn = { sizeof(SLAPD_SCHEMA_DN)-1,
			SLAPD_SCHEMA_DN };
		vals[0].bv_val = strchr( rdn.bv_val, '=' );

		if( vals[0].bv_val == NULL ) {
			*text = "improperly configured subschema subentry";
			return LDAP_OTHER;
		}

		vals[0].bv_val++;
		vals[0].bv_len = rdn.bv_len - (vals[0].bv_val - rdn.bv_val);
		rdn.bv_len -= vals[0].bv_len + 1;

		rc = slap_bv2ad( &rdn, &desc, text );

		if( rc != LDAP_SUCCESS ) {
			entry_free( e );
			*text = "improperly configured subschema subentry";
			return LDAP_OTHER;
		}

		attr_merge( e, desc, vals );
	}

	if ( syn_schema_info( e ) 
		|| mr_schema_info( e )
		|| at_schema_info( e )
		|| oc_schema_info( e ) )
	{
		/* Out of memory, do something about it */
		entry_free( e );
		*text = "out of memory";
		return LDAP_OTHER;
	}
	
	*entry = e;
	return LDAP_SUCCESS;
}
#endif

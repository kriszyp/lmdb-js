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
schema_info( Entry **entry, char **text )
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
#else
	char *ad_objectClass = "objectClass";
#endif

	Entry		*e;
	struct berval	val;
	struct berval	*vals[2];

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	e->e_dn = ch_strdup( SLAPD_SCHEMA_DN );
	e->e_ndn = ch_strdup( SLAPD_SCHEMA_DN );
	(void) dn_normalize( e->e_ndn );
	e->e_private = NULL;

	val.bv_val = "top";
	val.bv_len = sizeof("top")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "LDAPsubentry";
	val.bv_len = sizeof("LDAPsubentry")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "subschema";
	val.bv_len = sizeof("subschema")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "extensibleObject";
	val.bv_len = sizeof("extensibleObject")-1;
	attr_merge( e, ad_objectClass, vals );

	{
		int rc;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		AttributeDescription *desc = NULL;
#else
		char *desc;
#endif
		char *rdn = ch_strdup( SLAPD_SCHEMA_DN );
		val.bv_val = strchr( rdn, '=' );

		if( val.bv_val == NULL ) {
			free( rdn );
			*text = "improperly configured subschema subentry";
			return LDAP_OTHER;
		}

		*val.bv_val = '\0';
		val.bv_len = strlen( ++val.bv_val );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		rc = slap_str2ad( rdn, &desc, text );

		if( rc != LDAP_SUCCESS ) {
			free( rdn );
			entry_free( e );
			*text = "improperly configured subschema subentry";
			return LDAP_OTHER;
		}
#else
		desc = rdn;
#endif

		attr_merge( e, desc, vals );
		free( rdn );
	}

	if ( syn_schema_info( e ) 
		|| mr_schema_info( e )
		|| at_schema_info( e )
		|| oc_schema_info( e ) )
	{
		/* Out of memory, do something about it */
		entry_free( e );
		text = "out of memory";
		return LDAP_OTHER;
	}
	
	*entry = e;
	return LDAP_SUCCESS;
}
#endif


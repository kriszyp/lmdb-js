/* schema.c - routines to manage schema definitions */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"
#include "lutil.h"


int
schema_info( Entry **entry, const char **text )
{
	AttributeDescription *ad_structuralObjectClass
		= slap_schema.si_ad_structuralObjectClass;
	AttributeDescription *ad_objectClass
		= slap_schema.si_ad_objectClass;
	AttributeDescription *ad_createTimestamp
		= slap_schema.si_ad_createTimestamp;
	AttributeDescription *ad_modifyTimestamp
		= slap_schema.si_ad_modifyTimestamp;

	Entry		*e;
	struct berval	vals[5];
	struct berval	nvals[5];

	e = (Entry *) SLAP_CALLOC( 1, sizeof(Entry) );
	if( e == NULL ) {
		/* Out of memory, do something about it */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"schema_info: SLAP_CALLOC failed - out of memory.\n", 0, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, 
			"schema_info: SLAP_CALLOC failed - out of memory.\n", 0, 0, 0 );
#endif
		*text = "out of memory";
		return LDAP_OTHER;
	}

	e->e_attrs = NULL;
	/* backend-specific schema info should be created by the
	 * backend itself
	 */
	ber_dupbv( &e->e_name, &global_schemadn );
	ber_dupbv( &e->e_nname, &global_schemandn );
	e->e_private = NULL;

	vals[0].bv_val = "subentry";
	vals[0].bv_len = sizeof("subentry")-1;
	if( attr_merge_one( e, ad_structuralObjectClass, vals, vals ) )
	{
		/* Out of memory, do something about it */
		entry_free( e );
		*text = "out of memory";
		return LDAP_OTHER;
	}

	vals[0].bv_val = "top";
	vals[0].bv_len = sizeof("top")-1;
	vals[1].bv_val = "subentry";
	vals[1].bv_len = sizeof("subentry")-1;
	vals[2].bv_val = "subschema";
	vals[2].bv_len = sizeof("subschema")-1;
	vals[3].bv_val = "extensibleObject";
	vals[3].bv_len = sizeof("extensibleObject")-1;
	vals[4].bv_val = NULL;
	if( attr_merge( e, ad_objectClass, vals, vals ) )
	{
		/* Out of memory, do something about it */
		entry_free( e );
		*text = "out of memory";
		return LDAP_OTHER;
	}

	{
		int rc;
		AttributeDescription *desc = NULL;
		struct berval rdn = global_schemadn;
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

		nvals[0].bv_val = strchr( global_schemandn.bv_val, '=' );
		assert( nvals[0].bv_val );
		nvals[0].bv_val++;
		nvals[0].bv_len = global_schemandn.bv_len -
			(nvals[0].bv_val - global_schemandn.bv_val);

		if( attr_merge_one( e, desc, vals, nvals ) )
		{
			/* Out of memory, do something about it */
			entry_free( e );
			*text = "out of memory";
			return LDAP_OTHER;
		}
	}

	{
		struct		tm *ltm;
#ifdef HAVE_GMTIME_R
		struct		tm ltm_buf;
#endif
		char		timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];

		/*
		 * According to RFC 2251:

   Servers SHOULD provide the attributes createTimestamp and
   modifyTimestamp in subschema entries, in order to allow clients to
   maintain their caches of schema information.

		 * to be conservative, we declare schema created 
		 * AND modified at server startup time ...
		 */

#ifdef HAVE_GMTIME_R
		ltm = gmtime_r( &starttime, &ltm_buf );
#else
		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
		ltm = gmtime( &starttime );
#endif /* HAVE_GMTIME_R */
		lutil_gentime( timebuf, sizeof(timebuf), ltm );
#ifndef HAVE_GMTIME_R
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif

		vals[0].bv_val = timebuf;
		vals[0].bv_len = strlen( timebuf );

		if( attr_merge_one( e, ad_createTimestamp, vals, vals ) )
		{
			/* Out of memory, do something about it */
			entry_free( e );
			*text = "out of memory";
			return LDAP_OTHER;
		}
		if( attr_merge_one( e, ad_modifyTimestamp, vals, vals ) )
		{
			/* Out of memory, do something about it */
			entry_free( e );
			*text = "out of memory";
			return LDAP_OTHER;
		}
	}

	if ( syn_schema_info( e ) 
		|| mr_schema_info( e )
		|| mru_schema_info( e )
		|| at_schema_info( e )
		|| oc_schema_info( e )
		|| cr_schema_info( e ) )
	{
		/* Out of memory, do something about it */
		entry_free( e );
		*text = "out of memory";
		return LDAP_OTHER;
	}
	
	*entry = e;
	return LDAP_SUCCESS;
}

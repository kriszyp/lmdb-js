/* root_dse.c - Provides the Root DSA-Specific Entry */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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

#include <ac/string.h>

#include "slap.h"
#include <ldif.h>
#include "lber_pvt.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

static struct berval supportedFeatures[] = {
	BER_BVC(LDAP_FEATURE_ALL_OP_ATTRS),			/* All Op Attrs (+) */
	BER_BVC(LDAP_FEATURE_OBJECTCLASS_ATTRS),	/* OCs in Attrs List (@class) */
	BER_BVC(LDAP_FEATURE_ABSOLUTE_FILTERS),		/* (&) and (|) search filters */
	BER_BVC(LDAP_FEATURE_LANGUAGE_TAG_OPTIONS), /* Language Tag Options */
	BER_BVC(LDAP_FEATURE_LANGUAGE_RANGE_OPTIONS),/* Language Range Options */

#ifdef LDAP_DEVEL
	BER_BVC(LDAP_FEATURE_SUBORDINATE_SCOPE),	/* "children" search scope */
	BER_BVC(LDAP_FEATURE_MODIFY_INCREMENT),		/* Modify/increment */
#endif
	{0,NULL}
};

static Entry	*usr_attr = NULL;

int
root_dse_info(
	Connection *conn,
	Entry **entry,
	const char **text )
{
	Entry		*e;
	struct berval vals[2], *bv;
	struct berval nvals[2];
	int		i, j;
	char ** supportedSASLMechanisms;

	AttributeDescription *ad_structuralObjectClass
		= slap_schema.si_ad_structuralObjectClass;
	AttributeDescription *ad_objectClass
		= slap_schema.si_ad_objectClass;
	AttributeDescription *ad_namingContexts
		= slap_schema.si_ad_namingContexts;
	AttributeDescription *ad_supportedExtension
		= slap_schema.si_ad_supportedExtension;
	AttributeDescription *ad_supportedLDAPVersion
		= slap_schema.si_ad_supportedLDAPVersion;
	AttributeDescription *ad_supportedSASLMechanisms
		= slap_schema.si_ad_supportedSASLMechanisms;
	AttributeDescription *ad_supportedFeatures
		= slap_schema.si_ad_supportedFeatures;
	AttributeDescription *ad_monitorContext
		= slap_schema.si_ad_monitorContext;
	AttributeDescription *ad_ref
		= slap_schema.si_ad_ref;

	vals[1].bv_val = NULL;
	nvals[1].bv_val = NULL;

	e = (Entry *) SLAP_CALLOC( 1, sizeof(Entry) );

	if( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"root_dse_info: SLAP_CALLOC failed", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"root_dse_info: SLAP_CALLOC failed", 0, 0, 0 );
#endif
		return LDAP_OTHER;
	}

	e->e_attrs = NULL;
	e->e_name.bv_val = ch_strdup( LDAP_ROOT_DSE );
	e->e_name.bv_len = sizeof( LDAP_ROOT_DSE )-1;
	e->e_nname.bv_val = ch_strdup( LDAP_ROOT_DSE );
	e->e_nname.bv_len = sizeof( LDAP_ROOT_DSE )-1;

	/* the DN is an empty string so no pretty/normalization is needed */
	assert( !e->e_name.bv_len );
	assert( !e->e_nname.bv_len );

	e->e_private = NULL;

	vals[0].bv_val = "top";
	vals[0].bv_len = sizeof("top")-1;
	if( attr_merge( e, ad_objectClass, vals, NULL ) ) {
		return LDAP_OTHER;
	}

	vals[0].bv_val = "OpenLDAProotDSE";
	vals[0].bv_len = sizeof("OpenLDAProotDSE")-1;
	if( attr_merge( e, ad_objectClass, vals, NULL ) ) {
		return LDAP_OTHER;
	}
	if( attr_merge( e, ad_structuralObjectClass, vals, NULL ) ) {
		return LDAP_OTHER;
	}

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_suffix == NULL
				|| backends[i].be_nsuffix == NULL ) {
			/* no suffix! */
			continue;
		}
		if ( backends[i].be_flags & SLAP_BFLAG_MONITOR ) {
			vals[0] = backends[i].be_suffix[0];
			nvals[0] = backends[i].be_nsuffix[0];
			if( attr_merge( e, ad_monitorContext, vals, nvals ) ) {
				return LDAP_OTHER;
			}
			continue;
		}
		if ( SLAP_GLUE_SUBORDINATE( &backends[i] ) ) {
			continue;
		}
		for ( j = 0; backends[i].be_suffix[j].bv_val != NULL; j++ ) {
			vals[0] = backends[i].be_suffix[j];
			nvals[0] = backends[i].be_nsuffix[0];
			if( attr_merge( e, ad_namingContexts, vals, nvals ) ) {
				return LDAP_OTHER;
			}
		}
	}

	/* altServer unsupported */

	/* supportedControl */
	if ( controls_root_dse_info( e ) != 0 ) {
		return LDAP_OTHER;
	}

	/* supportedExtension */
	if ( exop_root_dse_info( e ) != 0 ) {
		return LDAP_OTHER;
	}

#ifdef LDAP_SLAPI
	/* netscape supportedExtension */
	for ( i = 0; (bv = slapi_int_get_supported_extop(i)) != NULL; i++ ) {
		vals[0] = *bv;
		if( attr_merge( e, ad_supportedExtension, vals, NULL )) {
			return LDAP_OTHER;
		}
	}
#endif /* LDAP_SLAPI */

	/* supportedFeatures */
	if( attr_merge( e, ad_supportedFeatures, supportedFeatures, NULL ) ) {
		return LDAP_OTHER;
	}

	/* supportedLDAPVersion */
	for ( i=LDAP_VERSION_MIN; i<=LDAP_VERSION_MAX; i++ ) {
		char buf[BUFSIZ];
		if (!( global_allows & SLAP_ALLOW_BIND_V2 ) &&
			( i < LDAP_VERSION3 ) )
		{
			/* version 2 and lower are disallowed */
			continue;
		}
		snprintf(buf, sizeof buf, "%d", i);
		vals[0].bv_val = buf;
		vals[0].bv_len = strlen( vals[0].bv_val );
		if( attr_merge( e, ad_supportedLDAPVersion, vals, NULL ) ) {
			return LDAP_OTHER;
		}
	}

	/* supportedSASLMechanism */
	supportedSASLMechanisms = slap_sasl_mechs( conn );

	if( supportedSASLMechanisms != NULL ) {
		for ( i=0; supportedSASLMechanisms[i] != NULL; i++ ) {
			vals[0].bv_val = supportedSASLMechanisms[i];
			vals[0].bv_len = strlen( vals[0].bv_val );
			if( attr_merge( e, ad_supportedSASLMechanisms, vals, NULL ) ) {
				return LDAP_OTHER;
			}
		}
		ldap_charray_free( supportedSASLMechanisms );
	}

	if ( default_referral != NULL ) {
		if( attr_merge( e, ad_ref, default_referral, NULL /* FIXME */ ) ) {
			return LDAP_OTHER;
		}
	}

	if( usr_attr != NULL) {
		Attribute *a;
		for( a = usr_attr->e_attrs; a != NULL; a = a->a_next ) {
			if( attr_merge( e, a->a_desc, a->a_vals,
				(a->a_nvals == a->a_vals) ? NULL : a->a_nvals ) )
			{
				return LDAP_OTHER;
			}
		}
	}

	*entry = e;
	return LDAP_SUCCESS;
}

/*
 * Read the entries specified in fname and merge the attributes
 * to the user defined rootDSE. Note thaat if we find any errors
 * what so ever, we will discard the entire entries, print an
 * error message and return.
 */
int read_root_dse_file( const char *fname )
{
	FILE	*fp;
	int rc = 0, lineno = 0, lmax = 0;
	char	*buf = NULL;

	if ( (fp = fopen( fname, "r" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"could not open rootdse attr file \"%s\" - absolute path?\n",
			fname, 0, 0 );
		perror( fname );
		return EXIT_FAILURE;
	}

	usr_attr = (Entry *) SLAP_CALLOC( 1, sizeof(Entry) );
	if( usr_attr == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"read_root_dse_file: SLAP_CALLOC failed", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"read_root_dse_file: SLAP_CALLOC failed", 0, 0, 0 );
#endif
		fclose( fp );
		return LDAP_OTHER;
	}
	usr_attr->e_attrs = NULL;

	while( ldif_read_record( fp, &lineno, &buf, &lmax ) ) {
		Entry *e = str2entry( buf );
		Attribute *a;

		if( e == NULL ) {
			fprintf( stderr, "root_dse: could not parse entry (line=%d)\n",
				lineno );
			rc = EXIT_FAILURE;
			break;
		}

		/* make sure the DN is the empty DN */
		if( e->e_nname.bv_len ) {
			fprintf( stderr,
				"root_dse: invalid rootDSE - dn=\"%s\" (line=%d)\n",
				e->e_dn, lineno );
			entry_free( e );
			rc = EXIT_FAILURE;
			break;
		}

		/*
		 * we found a valid entry, so walk thru all the attributes in the
		 * entry, and add each attribute type and description to the
		 * usr_attr entry
		 */

		for(a = e->e_attrs; a != NULL; a = a->a_next) {
			if( attr_merge( usr_attr, a->a_desc, a->a_vals,
				(a->a_nvals == a->a_vals) ? NULL : a->a_nvals ) )
			{
				rc = LDAP_OTHER;
				break;
			}
		}

		entry_free( e );
		if (rc) break;
	}

	if (rc) {
		entry_free( usr_attr );
		usr_attr = NULL;
	}

	ch_free( buf );

	fclose( fp );

	Debug(LDAP_DEBUG_CONFIG, "rootDSE file %s read.\n", fname, 0, 0);
	return rc;
}

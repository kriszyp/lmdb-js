/* $OpenLDAP$ */
/* root_dse.c - Provides the ROOT DSA-Specific Entry
 *
 * Copyright 1999-2000 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include <ldif.h>

static char *supportedFeatures[] = {
	"1.3.6.1.4.1.4203.1.5.1", /* All Operational Attributes ("+") */
	"1.3.6.1.4.1.4203.1.5.2", /* OCs in Attributes List */
	NULL
};

static Entry	*usr_attr = NULL;

int
root_dse_info(
	Connection *conn,
	Entry **entry,
	const char **text )
{
	char buf[BUFSIZ];
	Entry		*e;
	struct berval	val;
	struct berval	*vals[2];
	int		i, j;
	char ** supportedSASLMechanisms;

	AttributeDescription *ad_structuralObjectClass
		= slap_schema.si_ad_structuralObjectClass;
	AttributeDescription *ad_objectClass
		= slap_schema.si_ad_objectClass;
	AttributeDescription *ad_namingContexts
		= slap_schema.si_ad_namingContexts;
	AttributeDescription *ad_supportedControl
		= slap_schema.si_ad_supportedControl;
	AttributeDescription *ad_supportedExtension
		= slap_schema.si_ad_supportedExtension;
	AttributeDescription *ad_supportedLDAPVersion
		= slap_schema.si_ad_supportedLDAPVersion;
	AttributeDescription *ad_supportedSASLMechanisms
		= slap_schema.si_ad_supportedSASLMechanisms;
	AttributeDescription *ad_supportedFeatures
		= slap_schema.si_ad_supportedFeatures;
	AttributeDescription *ad_ref
		= slap_schema.si_ad_ref;

	Attribute *a;

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	e->e_dn = ch_strdup( LDAP_ROOT_DSE );
	e->e_ndn = ch_strdup( LDAP_ROOT_DSE );
	(void) dn_normalize( e->e_ndn );
	e->e_private = NULL;

	val.bv_val = "OpenLDAProotDSE";
	val.bv_len = sizeof("OpenLDAProotDSE")-1;
	attr_merge( e, ad_structuralObjectClass, vals );

	val.bv_val = "top";
	val.bv_len = sizeof("top")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "OpenLDAProotDSE";
	val.bv_len = sizeof("OpenLDAProotDSE")-1;
	attr_merge( e, ad_objectClass, vals );

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_glueflags & SLAP_GLUE_SUBORDINATE )
			continue;
		for ( j = 0; backends[i].be_suffix[j] != NULL; j++ ) {
			val.bv_val = backends[i].be_suffix[j];
			val.bv_len = strlen( val.bv_val );
			attr_merge( e, ad_namingContexts, vals );
		}
	}

	/* altServer unsupported */

	/* supportedControl */
	for ( i=0; supportedControls[i] != NULL; i++ ) {
		val.bv_val = supportedControls[i];
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, ad_supportedControl, vals );
	}

	/* supportedExtension */
	for ( i=0; (val.bv_val = get_supported_extop(i)) != NULL; i++ ) {
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, ad_supportedExtension, vals );
	}

	/* supportedFeatures */
	for ( i=0; supportedFeatures[i] != NULL; i++ ) {
		val.bv_val = supportedFeatures[i];
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, ad_supportedFeatures, vals );
	}

	/* supportedLDAPVersion */
	for ( i=LDAP_VERSION_MIN; i<=LDAP_VERSION_MAX; i++ ) {
		if (( global_disallows & SLAP_DISALLOW_BIND_V2 ) &&
			( i < LDAP_VERSION3 ) )
		{
			/* version 2 and lower are disallowed */
			continue;
		}
		sprintf(buf,"%d",i);
		val.bv_val = buf;
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, ad_supportedLDAPVersion, vals );
	}

	/* supportedSASLMechanism */
	supportedSASLMechanisms = slap_sasl_mechs( conn );

	if( supportedSASLMechanisms != NULL ) {
		for ( i=0; supportedSASLMechanisms[i] != NULL; i++ ) {
			val.bv_val = supportedSASLMechanisms[i];
			val.bv_len = strlen( val.bv_val );
			attr_merge( e, ad_supportedSASLMechanisms, vals );
		}
		charray_free( supportedSASLMechanisms );
	}

	if ( default_referral != NULL ) {
		attr_merge( e, ad_ref, default_referral );
	}

	if( usr_attr != NULL) {
		for(a = usr_attr->e_attrs; a != NULL; a = a->a_next) {
			attr_merge( e, a->a_desc, a->a_vals );
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

	Attribute *a;

	if ( (fp = fopen( fname, "r" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"could not open rootdse attr file \"%s\" - absolute path?\n",
			fname, 0, 0 );
		perror( fname );
		return EXIT_FAILURE;
	}

	usr_attr = (Entry *) ch_calloc( 1, sizeof(Entry) );
	usr_attr->e_attrs = NULL;

	while( ldif_read_record( fp, &lineno, &buf, &lmax ) ) {
		Entry *e = str2entry( buf );

		if( e == NULL ) {
			fprintf( stderr, "root_dse: could not parse entry (line=%d)\n",
				lineno );
			entry_free( e );
			entry_free( usr_attr );
			usr_attr = NULL;
			return EXIT_FAILURE;
		}

		if( dn_normalize( e->e_ndn ) == NULL ) {
			fprintf( stderr, "root_dse: invalid dn=\"%s\" (line=%d)\n",
				e->e_dn, lineno );
			entry_free( e );
			entry_free( usr_attr );
			usr_attr = NULL;
			return EXIT_FAILURE;
		}

		/* make sure the DN is a valid rootdse(rootdse is a null string) */
		if( strcmp(e->e_ndn, "") != 0 ) {
			fprintf( stderr,
				"root_dse: invalid rootDSE - dn=\"%s\" (line=%d)\n",
				e->e_dn, lineno );
			entry_free( e );
			entry_free( usr_attr );
			usr_attr = NULL;
			return EXIT_FAILURE;
		}

		/*
		 * we found a valid entry, so walk thru all the attributes in the
		 * entry, and add each attribute type and description to the
		 * usr_attr entry
		 */

		for(a = e->e_attrs; a != NULL; a = a->a_next) {
			attr_merge( usr_attr, a->a_desc, a->a_vals );
		}

		entry_free( e );
	}

	ch_free( buf );

	Debug(LDAP_DEBUG_CONFIG,"rootDSE file %s read.\n", fname, 0, 0);
	return rc;
}

/* schema_init.c - init builtin schema */
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

int schema_init_done = 0;

struct slap_internal_schema slap_schema;

#define objectClassIndexer NULL
#define objectClassFilter NULL

static int
objectClassMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	ObjectClass *oc = oc_find( value->bv_val );
	ObjectClass *asserted = oc_find( a->bv_val );

	if( asserted == NULL ) {
		if( isdigit( *value->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return LDAP_CONSTRAINT_VIOLATION;
	}

	if ( oc == NULL ) {
		return LDAP_CONSTRAINT_VIOLATION;
	}

#if 0
	Debug( LDAP_DEBUG_TRACE, "objectClassMatch(%s,%s)\n",
		value->bv_val, a->bv_val, NULL );
#endif

	*matchp = !is_object_subclass( asserted, oc );

	Debug( LDAP_DEBUG_TRACE, "\treturns %d\n",
		*matchp, NULL, NULL );

	return LDAP_SUCCESS;
}

struct slap_schema_oc_map {
	char *ssom_name;
	size_t ssom_offset;
} oc_map[] = {
	{ "top", offsetof(struct slap_internal_schema, si_oc_top) },
	{ "extensibleObject", offsetof(struct slap_internal_schema, si_oc_extensibleObject) },
	{ "alias", offsetof(struct slap_internal_schema, si_oc_alias) },
	{ "referral", offsetof(struct slap_internal_schema, si_oc_referral) },
	{ "LDAProotDSE", offsetof(struct slap_internal_schema, si_oc_rootdse) },
	{ "LDAPsubentry", offsetof(struct slap_internal_schema, si_oc_subentry) },
	{ "subschema", offsetof(struct slap_internal_schema, si_oc_subschema) },
	{ NULL, 0 }
};

struct slap_schema_ad_map {
	char *ssam_name;
	slap_mr_match_func *ssam_match;
	slap_mr_indexer_func *ssam_indexer;
	slap_mr_filter_func *ssam_filter;
	size_t ssam_offset;
} ad_map[] = {
	{ "objectClass",
		objectClassMatch, objectClassIndexer, objectClassFilter,
		offsetof(struct slap_internal_schema, si_ad_objectClass) },

	/* user entry operational attributes */
	{ "creatorsName", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_creatorsName) },
	{ "createTimestamp", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_createTimestamp) },
	{ "modifiersName", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifiersName) },
	{ "modifyTimestamp", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifyTimestamp) },
	{ "subschemaSubentry", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_subschemaSubentry) },

	/* root DSE attributes */
	{ "namingContexts", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
	{ "supportedSASLMechanisms", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },

	/* subschema subentry attributes */
	{ "attributeTypes", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "ldapSyntaxes", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ldapSyntaxes) },
	{ "matchingRules", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "objectClasses", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },

	/* knowledge information */
	{ "aliasedObjectName", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_aliasedObjectName) },
	{ "ref", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ref) },

	/* access control internals */
	{ "entry", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entry) },
	{ "children", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_children) },
#ifdef SLAPD_ACI_ENABLED
	{ "OpenLDAPaci", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_aci) },
#endif

	{ "userPassword", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_userPassword) },
	{ "authPassword", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_authPassword) },
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	{ "krbName", NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_krbName) },
#endif

	{ NULL, NULL, NULL, NULL, 0 }
};


int
schema_prep( void )
{
	int i;
	/* we should only be called once after schema_init() was called */
	assert( schema_init_done == 1 );

	for( i=0; oc_map[i].ssom_name; i++ ) {
		ObjectClass ** ocp = (ObjectClass **)
			&(((char *) &slap_schema)[oc_map[i].ssom_offset]);

		*ocp = oc_find( oc_map[i].ssom_name );

		if( *ocp == NULL ) {
			fprintf( stderr,
				"No objectClass \"%s\" defined in schema\n",
				oc_map[i].ssom_name );
			return LDAP_OBJECT_CLASS_VIOLATION;
		}
	}

	for( i=0; ad_map[i].ssam_name; i++ ) {
		int rc;
		const char *text;

		AttributeDescription ** adp = (AttributeDescription **)
			&(((char *) &slap_schema)[ad_map[i].ssam_offset]);

		*adp = NULL;

		rc = slap_str2ad( ad_map[i].ssam_name, adp, &text );

		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr,
				"No attribute \"%s\" defined in schema\n",
				ad_map[i].ssam_name );
			return rc;
		}

		if( ad_map[i].ssam_match ) {
			/* install custom matching routine */
			(*adp)->ad_type->sat_equality->smr_match = ad_map[i].ssam_match;
		}
	}

	++schema_init_done;
	return LDAP_SUCCESS;
}

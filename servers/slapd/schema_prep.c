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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
struct slap_internal_schema slap_schema;

static int
objectClassMatch(
	int *match,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	ObjectClass *oc = oc_find( value->bv_val );
	ObjectClass *asserted = oc_find( ((struct berval *) assertedValue)->bv_val );

	*match = ( oc == NULL || oc != asserted );
	return LDAP_SUCCESS;
}

struct slap_schema_oc_map {
	char *ssom_name;
	size_t ssom_offset;
} oc_map[] = {
	{ "top", offsetof(struct slap_internal_schema, si_oc_top) },
	{ "alias", offsetof(struct slap_internal_schema, si_oc_alias) },
	{ "referral", offsetof(struct slap_internal_schema, si_oc_referral) },
	{ "LDAProotDSE", offsetof(struct slap_internal_schema, si_oc_rootdse) },
	{ "LDAPsubentry", offsetof(struct slap_internal_schema, si_oc_subentry) },
	{ "subschema", offsetof(struct slap_internal_schema, si_oc_subschema) },
	{ "groupOfNames", offsetof(struct slap_internal_schema, si_oc_groupOfNames) },
	{ NULL, 0 }
};

struct slap_schema_ad_map {
	char *ssam_name;
	slap_mr_match_func *ssam_match;
	size_t ssam_offset;
} ad_map[] = {
	{ "objectClass", objectClassMatch,
		offsetof(struct slap_internal_schema, si_ad_objectClass) },

	/* user entry operational attributes */
	{ "creatorsName", NULL,
		offsetof(struct slap_internal_schema, si_ad_creatorsName) },
	{ "createTimestamp", NULL,
		offsetof(struct slap_internal_schema, si_ad_createTimestamp) },
	{ "modifiersName", NULL,
		offsetof(struct slap_internal_schema, si_ad_modifiersName) },
	{ "modifyTimestamp", NULL,
		offsetof(struct slap_internal_schema, si_ad_modifyTimestamp) },
	{ "subschemaSubentry", NULL,
		offsetof(struct slap_internal_schema, si_ad_subschemaSubentry) },

	/* root DSE attributes */
	{ "namingContexts", NULL,
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl", NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension", NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion", NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
#ifdef SLAPD_ACI_ENABLED
	{ "supportedACIMechanisms", NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedACIMechanisms) },
#endif
	{ "supportedSASLMechanisms", NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },

	/* subschema subentry attributes */
	{ "attributeTypes", NULL,
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "ldapSyntaxes", NULL,
		offsetof(struct slap_internal_schema, si_ad_ldapSyntaxes) },
	{ "matchingRules", NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "objectClasses", NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },

	/* knowledge information */
	{ "aliasedObjectName", NULL,
		offsetof(struct slap_internal_schema, si_ad_aliasedObjectName) },
	{ "ref", NULL,
		offsetof(struct slap_internal_schema, si_ad_ref) },

	/* access control information */
	{ "entry", NULL,
		offsetof(struct slap_internal_schema, si_ad_entry) },
	{ "children", NULL,
		offsetof(struct slap_internal_schema, si_ad_children) },
	{ "distinguishedName", NULL,
		offsetof(struct slap_internal_schema, si_ad_distinguishedName) },
	{ "member", NULL,
		offsetof(struct slap_internal_schema, si_ad_member) },
#ifdef SLAPD_ACI_ENABLED
	{ "aci", NULL,
		offsetof(struct slap_internal_schema, si_ad_aci) },
#endif

	{ "userPassword", NULL,
		offsetof(struct slap_internal_schema, si_ad_userPassword) },
	{ "authPassword", NULL,
		offsetof(struct slap_internal_schema, si_ad_authPassword) },
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	{ "krbName", NULL,
		offsetof(struct slap_internal_schema, si_ad_krbName) },
#endif

	{ NULL, NULL, 0 }
};

#endif

int
schema_prep( void )
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	int i;
#endif
	/* we should only be called once after schema_init() was called */
	assert( schema_init_done == 1 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
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
#endif

	++schema_init_done;
	return LDAP_SUCCESS;
}

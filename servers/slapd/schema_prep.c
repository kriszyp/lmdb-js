/* schema_init.c - init builtin schema */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"
#include "ldap_pvt_uc.h"

int schema_init_done = 0;

struct slap_internal_schema slap_schema;

static int
objectClassMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	ObjectClass *oc = oc_bvfind( value );
	ObjectClass *asserted = oc_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return SLAPD_COMPARE_UNDEFINED;
	}

	if ( oc == NULL ) {
		/* unrecognized stored value */
		return SLAPD_COMPARE_UNDEFINED;
	}

	if( SLAP_IS_MR_VALUE_SYNTAX_MATCH( flags ) ) {
		*matchp = ( asserted != oc );
	} else {
		*matchp = !is_object_subclass( asserted, oc );
	}

#if 0
#ifdef NEW_LOGGING
	LDAP_LOG(( "schema", LDAP_LEVEL_ENTRY,
		   "objectClassMatch(%s, %s) = %d\n",
		   value->bv_val, a->bv_val, *matchp ));
#else
	Debug( LDAP_DEBUG_TRACE, "objectClassMatch(%s,%s) = %d\n",
		value->bv_val, a->bv_val, *matchp );
#endif
#endif

	return LDAP_SUCCESS;
}

static int
structuralObjectClassMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	ObjectClass *oc = oc_bvfind( value );
	ObjectClass *asserted = oc_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return SLAPD_COMPARE_UNDEFINED;
	}

	if ( oc == NULL ) {
		/* unrecognized stored value */
		return SLAPD_COMPARE_UNDEFINED;
	}

	*matchp = ( asserted != oc );

#if 0
#ifdef NEW_LOGGING
	LDAP_LOG(( "schema", LDAP_LEVEL_ENTRY,
		   "structuralObjectClassMatch( %s, %s ) = %d\n",
		   value->bv_val, a->bv_val, *matchp ));
#else
	Debug( LDAP_DEBUG_TRACE, "structuralObjectClassMatch(%s,%s) = %d\n",
		value->bv_val, a->bv_val, *matchp );
#endif
#endif

	return LDAP_SUCCESS;
}

static struct slap_schema_oc_map {
	char *ssom_name;
	char *ssom_defn;
	ObjectClassSchemaCheckFN *ssom_check;
	size_t ssom_offset;
} oc_map[] = {
	{ "top", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_top) },
	{ "extensibleObject", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_extensibleObject) },
	{ "alias", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_alias) },
	{ "referral", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_referral) },
	{ "LDAProotDSE", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_rootdse) },
	{ "subentry", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_subentry) },
	{ "subschema", NULL, 0,
		offsetof(struct slap_internal_schema, si_oc_subschema) },
	{ NULL, 0 }
};

static struct slap_schema_ad_map {
	char *ssam_name;
	char *ssam_defn;
	AttributeTypeSchemaCheckFN *ssam_check;
	slap_mr_match_func *ssam_match;
	slap_mr_indexer_func *ssam_indexer;
	slap_mr_filter_func *ssam_filter;
	size_t ssam_offset;
} ad_map[] = {
	{ "objectClass", "( 2.5.4.0 NAME 'objectClass' "
			"DESC 'RFC2256: object classes of the entity' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
			NULL,
		objectClassMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClass) },
	{ "structuralObjectClass", "( 2.5.21.9 NAME 'structuralObjectClass' "
			"DESC 'X.500(93): structural object class of entry' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"NO-USER-MODIFICATION SINGLE-VALUE USAGE directoryOperation )",
		NULL,
		structuralObjectClassMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_structuralObjectClass) },

	/* user entry operational attributes */
	{ "createTimestamp", "( 2.5.18.1 NAME 'createTimestamp' "
			"DESC 'RFC2252: time which object was created' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_createTimestamp) },
	{ "modifyTimestamp", "( 2.5.18.2 NAME 'modifyTimestamp' "
			"DESC 'RFC2252: time which object was last modified' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifyTimestamp) },
	{ "creatorsName", "( 2.5.18.3 NAME 'creatorsName' "
			"DESC 'RFC2252: name of creator' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_creatorsName) },
	{ "modifiersName", "( 2.5.18.4 NAME 'modifiersName' "
			"DESC 'RFC2252: name of last modifier' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifiersName) },
	{ "hasSubordinates", "( 2.5.18.9 NAME 'hasSubordinates' "
			"DESC 'X.501: entry has children' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_hasSubordinates) },
	{ "subschemaSubentry", "( 2.5.18.10 NAME 'subschemaSubentry' "
			"DESC 'RFC2252: name of controlling subschema entry' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION "
			"SINGLE-VALUE USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_subschemaSubentry) },

	{ "entryUUID", "( 1.3.6.1.4.1.4203.666.1.6 NAME 'entryUUID' "   
			"DESC 'LCUP/LDUP: universally unique identifier' "
			"EQUALITY octetStringMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{64} "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryUUID) },
	{ "entryCSN", "( 1.3.6.1.4.1.4203.666.1.7 NAME 'entryCSN' "
			"DESC 'LCUP/LDUP: change sequence number' "
			"EQUALITY octetStringMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{64} "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryCSN) },

	/* root DSE attributes */
	{ "namingContexts", "( 1.3.6.1.4.1.1466.101.120.5 "
			"NAME 'namingContexts' "
			"DESC 'RFC2252: naming contexts' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl", "( 1.3.6.1.4.1.1466.101.120.13 "
			"NAME 'supportedControl' "
		   "DESC 'RFC2252: supported controls' "
		   "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension", "( 1.3.6.1.4.1.1466.101.120.7 "
			"NAME 'supportedExtension' "
			"DESC 'RFC2252: supported extended operations' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion", "( 1.3.6.1.4.1.1466.101.120.15 "
			"NAME 'supportedLDAPVersion' "
			"DESC 'RFC2252: supported LDAP versions' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
	{ "supportedSASLMechanisms", "( 1.3.6.1.4.1.1466.101.120.14 "
			"NAME 'supportedSASLMechanisms' "
			"DESC 'RFC2252: supported SASL mechanisms'"
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },
	{ "supportedFeatures", "( 1.3.6.1.4.1.4203.1.3.5 "
			"NAME 'supportedFeatures' "
			"DESC 'features supported by the server' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedFeatures) },

	/* subschema subentry attributes */
	{ "matchingRules", "( 2.5.21.4 NAME 'matchingRules' "
			"DESC 'RFC2252: matching rules' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "attributeTypes", "( 2.5.21.5 NAME 'attributeTypes' "
			"DESC 'RFC2252: attribute types' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "objectClasses", "( 2.5.21.6 NAME 'objectClasses' "
			"DESC 'RFC2252: object classes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },

	{ "ldapSyntaxes", "( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' "
			"DESC 'RFC2252: LDAP syntaxes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ldapSyntaxes) },

	/* knowledge information */
	{ "aliasedObjectName", "( 2.5.4.1 "
			"NAME ( 'aliasedObjectName' 'aliasedEntryName' ) "
			"DESC 'RFC2256: name of aliased object' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_aliasedObjectName) },
	{ "ref", "( 2.16.840.1.113730.3.1.34 NAME 'ref' "
			"DESC 'namedref: subordinate referral URL' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"USAGE distributedOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ref) },

	/* access control internals */
	{ "entry", "( 1.3.6.1.4.1.4203.1.3.1 "
			"NAME 'entry' "
			"DESC 'OpenLDAP ACL entry pseudo-attribute' "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entry) },
	{ "children", "( 1.3.6.1.4.1.4203.1.3.2 "
			"NAME 'children' "
			"DESC 'OpenLDAP ACL children pseudo-attribute' "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_children) },
#ifdef SLAPD_ACI_ENABLED
	{ "OpenLDAPaci", "( 1.3.6.1.4.1.4203.666.1.5 "
			"NAME 'OpenLDAPaci' "
			"DESC 'OpenLDAP access control information (experimental)' "
			"EQUALITY OpenLDAPaciMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.2.1 "
			"USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_aci) },
#endif

	/* userApplication attributes */
	{ "name", "( 2.5.4.41 NAME 'name' "
			"DESC 'RFC2256: common supertype of name attributes' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_name) },
	{ "cn", "( 2.5.4.3 NAME ( 'cn' 'commonName' ) "
			"DESC 'RFC2256: common name(s) for which the entity is known by' "
			"SUP name )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_cn) },

	{ "userPassword", "( 2.5.4.35 NAME 'userPassword' "
			"DESC 'RFC2256/2307: password of user' "
			"EQUALITY octetStringMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_userPassword) },

#ifdef SLAPD_AUTHPASSWD
	{ "authPassword", NULL,
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_authPassword) },
#endif
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	{ "krbName", NULL,
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_krbName) },
#endif

	{ NULL, NULL, NULL, NULL, NULL, NULL, 0 }
};

static AttributeType slap_at_undefined = {
	{ "1.1.1", NULL, NULL, 1, NULL,
		NULL, NULL, NULL, NULL,
		0, 0, 0, 1, 3 }, /* LDAPAttributeType */
	{ sizeof("UNDEFINED")-1, "UNDEFINED" }, /* cname */
	NULL, /* sup */
	NULL, /* subtypes */
	NULL, NULL, NULL, NULL,	/* matching rules */
	NULL, /* syntax (this may need to be defined) */
	(AttributeTypeSchemaCheckFN *) 0, /* schema check function */
	NULL, /* attribute description */
	NULL  /* next */
	/* mutex (don't know how to initialize it :) */
};

static struct slap_schema_mr_map {
	char *ssmm_name;
	size_t ssmm_offset;
} mr_map[] = {
	{ "distinguishedNameMatch",
		offsetof(struct slap_internal_schema, si_mr_distinguishedNameMatch) },
	{ "integerMatch",
		offsetof(struct slap_internal_schema, si_mr_integerMatch) },
	{ NULL, 0 }
};

static struct slap_schema_syn_map {
	char *sssm_name;
	size_t sssm_offset;
} syn_map[] = {
	{ "1.3.6.1.4.1.1466.115.121.1.12",
		offsetof(struct slap_internal_schema, si_syn_distinguishedName) },
	{ "1.3.6.1.4.1.1466.115.121.1.27",
		offsetof(struct slap_internal_schema, si_syn_integer) },
	{ NULL, 0 }
};

int
slap_schema_load( void )
{
	return LDAP_SUCCESS;
}

int
slap_schema_check( void )
{
	int i;
	/* we should only be called once after schema_init() was called */
	assert( schema_init_done == 1 );

	for( i=0; syn_map[i].sssm_name; i++ ) {
		Syntax ** synp = (Syntax **)
			&(((char *) &slap_schema)[syn_map[i].sssm_offset]);

		*synp = syn_find( syn_map[i].sssm_name );

		if( *synp == NULL ) {
			fprintf( stderr, "slap_schema_check: "
				"No syntax \"%s\" defined in schema\n",
				syn_map[i].sssm_name );
			return LDAP_INVALID_SYNTAX;
		}
	}

	for( i=0; mr_map[i].ssmm_name; i++ ) {
		MatchingRule ** mrp = (MatchingRule **)
			&(((char *) &slap_schema)[mr_map[i].ssmm_offset]);

		*mrp = mr_find( mr_map[i].ssmm_name );

		if( *mrp == NULL ) {
			fprintf( stderr, "slap_schema_check: "
				"No matching rule \"%s\" defined in schema\n",
				mr_map[i].ssmm_name );
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	slap_at_undefined.sat_syntax = syn_find( SLAPD_OCTETSTRING_SYNTAX );
	if( slap_at_undefined.sat_syntax == NULL ) {
		fprintf( stderr, "slap_schema_check: "
			"No octetString syntax \"" SLAPD_OCTETSTRING_SYNTAX "\"\n" );
		return LDAP_INVALID_SYNTAX;
	}
	slap_schema.si_at_undefined = &slap_at_undefined;

	for( i=0; ad_map[i].ssam_name; i++ ) {
		int rc;
		const char *text;

		AttributeDescription ** adp = (AttributeDescription **)
			&(((char *) &slap_schema)[ad_map[i].ssam_offset]);

		*adp = NULL;

		rc = slap_str2ad( ad_map[i].ssam_name, adp, &text );

		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "slap_schema_check: "
				"No attribute \"%s\" defined in schema\n",
				ad_map[i].ssam_name );
			return rc;
		}

		if( ad_map[i].ssam_match ) {
			/* install custom matching routine */
			(*adp)->ad_type->sat_equality->smr_match = ad_map[i].ssam_match;
		}
	}

	for( i=0; oc_map[i].ssom_name; i++ ) {
		ObjectClass ** ocp = (ObjectClass **)
			&(((char *) &slap_schema)[oc_map[i].ssom_offset]);

		*ocp = oc_find( oc_map[i].ssom_name );

		if( *ocp == NULL ) {
			fprintf( stderr, "slap_schema_check: "
				"No objectClass \"%s\" defined in schema\n",
				oc_map[i].ssom_name );
			return LDAP_OBJECT_CLASS_VIOLATION;
		}
	}

	++schema_init_done;
	return LDAP_SUCCESS;
}

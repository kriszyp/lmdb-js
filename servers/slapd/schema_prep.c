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
	{ "top", "( 2.5.6.0 NAME 'top' "
			"DESC 'top of the superclass chain' "
			"ABSTRACT MUST objectClass )",
		0, offsetof(struct slap_internal_schema, si_oc_top) },
	{ "extensibleObject", "( 1.3.6.1.4.1.1466.101.120.111 "
			"NAME 'extensibleObject' "
			"DESC 'RFC2252: extensible object' "
			"SUP top AUXILIARY )",
		0, offsetof(struct slap_internal_schema, si_oc_extensibleObject) },
	{ "alias", "( 2.5.6.1 NAME 'alias' "
			"DESC 'RFC2256: an alias' "
			"SUP top STRUCTURAL "
			"MUST aliasedObjectName )",
		0, offsetof(struct slap_internal_schema, si_oc_alias) },
	{ "referral", "( 2.16.840.1.113730.3.2.6 NAME 'referral' "
			"DESC 'namedref: named subordinate referral' "
			"SUP top STRUCTURAL MUST ref )",
		0, offsetof(struct slap_internal_schema, si_oc_referral) },
	{ "LDAProotDSE", "( 1.3.6.1.4.1.4203.1.4.1 "
			"NAME ( 'OpenLDAProotDSE' 'LDAProotDSE' ) "
			"DESC 'OpenLDAP Root DSE object' "
			"SUP top STRUCTURAL MAY cn )",
		0, offsetof(struct slap_internal_schema, si_oc_rootdse) },
	{ "subentry", "( 2.5.20.0 NAME 'subentry' "
			"SUP top STRUCTURAL "
			"MUST ( cn $ subtreeSpecification ) )",
		0, offsetof(struct slap_internal_schema, si_oc_subentry) },
	{ "subschema", "( 2.5.20.1 NAME 'subschema' "
		"DESC 'RFC2252: controlling subschema (sub)entry' "
		"AUXILIARY"
		"MAY ( dITStructureRules $ nameForms $ ditContentRules $ "
			"objectClasses $ attributeTypes $ matchingRules $ "
			"matchingRuleUse ) )",
		0, offsetof(struct slap_internal_schema, si_oc_subschema) },
	{ "collectiveAttributes", "( 2.5.20.2 "
			"NAME 'collectiveAttributes' "
			"AUXILIARY )",
		0,
		offsetof(struct slap_internal_schema, si_oc_collectiveAttributes) },
	{ NULL, 0 }
};

static AttributeTypeSchemaCheckFN rootDseAttribute;
static AttributeTypeSchemaCheckFN subentryAttribute;
static AttributeTypeSchemaCheckFN referralAttribute;

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

	/* user entry operational attributes */
	{ "structuralObjectClass", "( 2.5.21.9 NAME 'structuralObjectClass' "
			"DESC 'X.500(93): structural object class of entry' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"NO-USER-MODIFICATION SINGLE-VALUE USAGE directoryOperation )",
		NULL,
		structuralObjectClassMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_structuralObjectClass) },
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
	{ "collectiveAttributeSubentry", "( 2.5.18.12 "
			"NAME 'collectiveAttributeSubentry' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"USAGE directoryOperation NO-USER-MODIFICATION )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_collectiveSubentry) },
	{ "collectiveExclusions", "( 2.5.18.7 NAME 'collectiveExclusions' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"USAGE directoryOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_collectiveExclusions) },

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
	{ "altServer", "( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' "
			"DESC 'RFC2252: alternative servers' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_altServer) },
	{ "namingContexts", "( 1.3.6.1.4.1.1466.101.120.5 "
			"NAME 'namingContexts' "
			"DESC 'RFC2252: naming contexts' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl", "( 1.3.6.1.4.1.1466.101.120.13 "
			"NAME 'supportedControl' "
		   "DESC 'RFC2252: supported controls' "
		   "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension", "( 1.3.6.1.4.1.1466.101.120.7 "
			"NAME 'supportedExtension' "
			"DESC 'RFC2252: supported extended operations' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion", "( 1.3.6.1.4.1.1466.101.120.15 "
			"NAME 'supportedLDAPVersion' "
			"DESC 'RFC2252: supported LDAP versions' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
	{ "supportedSASLMechanisms", "( 1.3.6.1.4.1.1466.101.120.14 "
			"NAME 'supportedSASLMechanisms' "
			"DESC 'RFC2252: supported SASL mechanisms'"
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },
	{ "supportedFeatures", "( 1.3.6.1.4.1.4203.1.3.5 "
			"NAME 'supportedFeatures' "
			"DESC 'features supported by the server' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedFeatures) },
	{ "vendorName", "( 1.3.6.1.1.4 NAME 'vendorName' "
			"DESC 'RFC3045: name of implementation vendor' "
			"EQUALITY 1.3.6.1.4.1.1466.109.114.1 "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_vendorName) },
	{ "vendorVersion", "( 1.3.6.1.1.5 NAME 'vendorVersion' "
			"DESC 'RFC3045: version of implementation' "
			"EQUALITY 1.3.6.1.4.1.1466.109.114.1 "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_vendorVersion) },

	/* subentry attributes */
	{ "administrativeRole", "( 2.5.18.5 NAME 'administrativeRole' "
			"EQUALITY objectIdentifierMatch "
			"USAGE directoryOperation "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_administrativeRole) },
	{ "subtreeSpecification", "( 2.5.18.6 NAME 'subtreeSpecification' "
			"SINGLE-VALUE "
			"USAGE directoryOperation "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_subtreeSpecification) },

	/* subschema subentry attributes */
	{ "ditStructureRules", "( 2.5.21.1 NAME 'dITStructureRules' "
			"DESC 'RFC2252: DIT structure rules' "
			"EQUALITY integerFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.17 "
			"USAGE directoryOperation ) ",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ditStructureRules) },
	{ "ditContentRules", "( 2.5.21.2 NAME 'dITContentRules' "
			"DESC 'RFC2252: DIT content rules' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ditContentRules) },
	{ "matchingRules", "( 2.5.21.4 NAME 'matchingRules' "
			"DESC 'RFC2252: matching rules' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "attributeTypes", "( 2.5.21.5 NAME 'attributeTypes' "
			"DESC 'RFC2252: attribute types' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "objectClasses", "( 2.5.21.6 NAME 'objectClasses' "
			"DESC 'RFC2252: object classes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },
	{ "nameForms", "( 2.5.21.7 NAME 'nameForms' "
			"DESC 'RFC2252: name forms ' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.35 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_nameForms) },
	{ "matchingRuleUse", "( 2.5.21.8 NAME 'matchingRuleUse' "
			"DESC 'RFC2252: matching rule uses' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRuleUse) },

	{ "ldapSyntaxes", "( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' "
			"DESC 'RFC2252: LDAP syntaxes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
		subentryAttribute, NULL, NULL, NULL,
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
		referralAttribute, NULL, NULL, NULL,
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

	{ "entryTtl", "( 1.3.6.1.4.1.1466.101.119.3 NAME 'entryTtl' "
			"DESC 'RFC2589: entry time-to-live' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE "
			"NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryTtl) },
	{ "dynamicSubtrees", "( 1.3.6.1.4.1.1466.101.119.4 "
			"NAME 'dynamicSubtrees' "
			"DESC 'RFC2589: dynamic subtrees' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_dynamicSubtrees) },

	/* userApplication attributes */
	{ "distinguishedName", "( 2.5.4.49 NAME 'distinguishedName' "
			"DESC 'RFC2256: common supertype of DN attributes' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_distinguishedName) },
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
	{ "authPassword", "( 1.3.6.1.4.1.4203.1.3.4 "
			"NAME 'authPassword' "
			"DESC 'RFC3112: authentication password attribute' "
			"EQUALITY 1.3.6.1.4.1.4203.1.2.2 "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.2 )",
		NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_authPassword) },
	{ "supportedAuthPasswordSchemes", "( 1.3.6.1.4.1.4203.1.3.3 "
			"NAME 'supportedAuthPasswordSchemes' "
			"DESC 'RFC3112: supported authPassword schemes' "
			"EQUALITY caseExactIA5Match "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{32} "
			"USAGE dSAOperation )",
		subschemaAttribute, NULL, NULL, NULL,
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
	int i;
	for( i=0; ad_map[i].ssam_name; i++ ) {
		if( ad_map[i].ssam_defn != NULL ) {
			LDAPAttributeType *at;
			int		code;
			const char	*err;

			at = ldap_str2attributetype( ad_map[i].ssam_defn,
				&code, &err, LDAP_SCHEMA_ALLOW_ALL );
			if ( !at ) {
				fprintf( stderr,
					"slap_schema_load: %s: %s before %s\n",
					 ad_map[i].ssam_name, ldap_scherr2str(code), err );
				return code;
			}

			if ( at->at_oid == NULL ) {
				fprintf( stderr, "slap_schema_load: "
					"attributeType \"%s\" has no OID\n",
					ad_map[i].ssam_name );
				return LDAP_OTHER;
			}

			code = at_add( at, &err );
			if ( code ) {
				fprintf( stderr, "slap_schema_load: "
					"%s: %s: \"%s\"\n",
					 ad_map[i].ssam_name, scherr2str(code), err );
				return code;
			}
			ldap_memfree( at );
		}
	}

	for( i=0; oc_map[i].ssom_name; i++ ) {
		LDAPObjectClass *oc;
		int		code;
		const char	*err;

		oc = ldap_str2objectclass( oc_map[i].ssom_defn, &code, &err,
			LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			fprintf( stderr, "slap_schema_load: "
				"%s: %s before %s\n",
				 oc_map[i].ssom_name, ldap_scherr2str(code), err );
			return code;
		}

		if ( oc->oc_oid == NULL ) {
			fprintf( stderr, "slap_schema_load: "
				"%s: objectclass has no OID\n",
				oc_map[i].ssom_name );
			return LDAP_OTHER;
		}

		code = oc_add(oc,&err);
		if ( code ) {
			fprintf( stderr, "slap_schema_load: "
				"%s: %s: \"%s\"\n",
				 oc_map[i].ssom_name, scherr2str(code), err);
			return code;
		}

		ldap_memfree(oc);
		return 0;
	}

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

		assert( *synp == NULL );

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

		assert( *mrp == NULL );

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

		assert( *adp == NULL );

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

		assert( *ocp == NULL );

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

static int rootDseAttribute (
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;
	if( e->e_nname.bv_len ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\"only allowed in the root DSE",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	/* we should not be called for the root DSE */
	assert( 0 );
	return LDAP_SUCCESS;
}

static int subentryAttribute (
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;
	if( !is_entry_subentry( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\"only allowed in the subentry",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int referralAttribute (
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;
	if( !is_entry_referral( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\"only allowed in the referral",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

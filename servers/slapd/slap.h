/* slap.h - stand alone ldap server include file */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _SLAP_H_
#define _SLAP_H_

#include "ldap_defaults.h"

#include <ac/stdlib.h>

#include <sys/types.h>
#include <ac/syslog.h>
#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/time.h>
#include <ac/param.h>

#ifdef HAVE_CYRUS_SASL
#include <sasl.h>
#endif

#include "avl.h"

#ifndef ldap_debug
#define ldap_debug slap_debug
#endif


#include "ldap_log.h"

#include <ldap.h>
#include <ldap_schema.h>

#include "ldap_pvt_thread.h"
#include "ldif.h"

LDAP_BEGIN_DECL

#define SERVICE_NAME  OPENLDAP_PACKAGE "-slapd"
#define SLAPD_ANONYMOUS "<anonymous>"

#ifdef f_next
#undef f_next /* name conflict between sys/file.h on SCO and struct filter */
#endif

/* LDAPMod.mod_op value ===> Must be kept in sync with ldap.h!
 *
 * This is a value used internally by the backends. It is needed to allow
 * adding values that already exist without getting an error as required by
 * modrdn when the new rdn was already an attribute value itself.
 * JCG 05/1999 (gomez@engr.sgi.com)
 */
#define SLAP_MOD_SOFTADD	0x1000

#define ON	1
#define OFF	(-1)
#define UNDEFINED 0

#define MAXREMATCHES 10


/* psuedo error code indicating abandoned operation */
#define SLAPD_ABANDON (-1)

/* psuedo error code indicating disconnect */
#define SLAPD_DISCONNECT (-2)


/* We assume "C" locale, that is US-ASCII */
#define ASCII_SPACE(c)	( (c) == ' ' )
#define ASCII_LOWER(c)	( (c) >= 'a' && (c) <= 'z' )
#define ASCII_UPPER(c)	( (c) >= 'A' && (c) <= 'Z' )
#define ASCII_ALPHA(c)	( ASCII_LOWER(c) || ASCII_UPPER(c) )
#define ASCII_DIGIT(c)	( (c) >= '0' && (c) <= '9' )
#define ASCII_ALNUM(c)	( ASCII_ALPHA(c) || ASCII_DIGIT(c) )

#define DN_SEPARATOR(c)	((c) == ',' || (c) == ';')
#define RDN_SEPARATOR(c)	((c) == ',' || (c) == ';' || (c) == '+')
#define RDN_NEEDSESCAPE(c)	((c) == '\\' || (c) == '"')

#define DESC_LEADCHAR(c)	( ASCII_ALPHA(c) )
#define DESC_CHAR(c)	( ASCII_ALNUM(c) || (c) == '-' )
#define OID_LEADCHAR(c)	( ASCII_DIGIT(c) )
#define OID_CHAR(c)	( ASCII_DIGIT(c) || (c) == '.' )

#define ATTR_LEADCHAR(c)	( DESC_LEADCHAR(c) || OID_LEADCHAR(c) )
#define ATTR_CHAR(c)	( DESC_CHAR((c)) || (c) == '.' )

#define AD_LEADCHAR(c)	( ATTR_CHAR(c) )
#define AD_CHAR(c)		( ATTR_CHAR(c) || (c) == ';' )

/* must match in schema_init.c */
#define SLAPD_DN_SYNTAX			"1.3.6.1.4.1.1466.115.121.1.12"
#define SLAPD_GROUP_ATTR		"member"
#define SLAPD_GROUP_CLASS		"groupOfNames"
#define SLAPD_ROLE_ATTR			"roleOccupant"
#define SLAPD_ROLE_CLASS		"organizationalRole"

#define SLAPD_ACI_SYNTAX		"1.3.6.1.4.1.4203.666.2.1"
#define SLAPD_ACI_ATTR			"OpenLDAPaci"

LIBSLAPD_F (int) slap_debug;

/*
 * Index types
 */
#define SLAP_INDEX_TYPE           0x00FFUL
#define SLAP_INDEX_UNDEFINED      0x0001UL
#define SLAP_INDEX_PRESENT        0x0002UL
#define SLAP_INDEX_EQUALITY       0x0004UL
#define SLAP_INDEX_APPROX         0x0008UL
#define SLAP_INDEX_SUBSTR         0x0010UL
#define SLAP_INDEX_EXTENDED		  0x0020UL

#define SLAP_INDEX_DEFAULT        SLAP_INDEX_EQUALITY

#define IS_SLAP_INDEX(mask, type)	(((mask) & (type)) == (type) )

#define SLAP_INDEX_SUBSTR_TYPE    0x0F00UL

#define SLAP_INDEX_SUBSTR_INITIAL ( SLAP_INDEX_SUBSTR | 0x0100UL ) 
#define SLAP_INDEX_SUBSTR_ANY     ( SLAP_INDEX_SUBSTR | 0x0200UL )
#define SLAP_INDEX_SUBSTR_FINAL   ( SLAP_INDEX_SUBSTR | 0x0400UL )
#define SLAP_INDEX_SUBSTR_DEFAULT ( SLAP_INDEX_SUBSTR \
	| SLAP_INDEX_SUBSTR_INITIAL | SLAP_INDEX_SUBSTR_FINAL )

#define SLAP_INDEX_FLAGS          0xF000UL
#define SLAP_INDEX_SUBTYPES       0x1000UL /* use index with subtypes */
#define SLAP_INDEX_AUTO_SUBTYPES  0x2000UL /* use mask with subtypes */
#define SLAP_INDEX_LANG           0x4000UL /* use index with lang subtypes */
#define SLAP_INDEX_AUTO_LANG      0x8000UL /* use mask with lang subtypes */

typedef long slap_index;

/*
 * there is a single index for each attribute.  these prefixes ensure
 * that there is no collision among keys.
 */
#define SLAP_INDEX_EQUALITY_PREFIX	'=' 	/* prefix for equality keys     */
#define SLAP_INDEX_APPROX_PREFIX	'~'		/* prefix for approx keys       */
#define SLAP_INDEX_SUBSTR_PREFIX	'*'		/* prefix for substring keys    */
#define SLAP_INDEX_CONT_PREFIX		'.'		/* prefix for continuation keys */
#define SLAP_INDEX_UNKNOWN_PREFIX	'?'		/* prefix for unknown keys */

/*
 * represents schema information for a database
 */
#define SLAP_SCHERR_OUTOFMEM		1
#define SLAP_SCHERR_CLASS_NOT_FOUND	2
#define SLAP_SCHERR_ATTR_NOT_FOUND	3
#define SLAP_SCHERR_DUP_CLASS		4
#define SLAP_SCHERR_DUP_ATTR		5
#define SLAP_SCHERR_DUP_SYNTAX		6
#define SLAP_SCHERR_DUP_RULE		7
#define SLAP_SCHERR_NO_NAME		8
#define SLAP_SCHERR_ATTR_INCOMPLETE	9
#define SLAP_SCHERR_MR_NOT_FOUND	10
#define SLAP_SCHERR_SYN_NOT_FOUND	11
#define SLAP_SCHERR_MR_INCOMPLETE	12

typedef struct slap_oid_macro {
	struct berval som_oid;
	char **som_names;
	struct slap_oid_macro *som_next;
} OidMacro;

/* forward declarations */
struct slap_syntax;
struct slap_matching_rule;

typedef int slap_syntax_validate_func LDAP_P((
	struct slap_syntax *syntax,
	struct berval * in));

typedef int slap_syntax_transform_func LDAP_P((
	struct slap_syntax *syntax,
	struct berval * in,
	struct berval ** out));

typedef struct slap_syntax {
	LDAP_SYNTAX			ssyn_syn;
#define ssyn_oid		ssyn_syn.syn_oid
#define ssyn_desc		ssyn_syn.syn_desc
#define ssyn_extensions		ssyn_syn.syn_extensions

	unsigned	ssyn_flags;

#define SLAP_SYNTAX_NONE	0x00U
#define SLAP_SYNTAX_BLOB	0x01U /* syntax treated as blob (audio) */
#define SLAP_SYNTAX_BINARY	0x02U /* binary transfer required (certificate) */
#define SLAP_SYNTAX_BER		0x04U /* stored using BER encoding (binary,certificate) */
#define SLAP_SYNTAX_HIDE	0x80U /* hide (do not publish) */

	slap_syntax_validate_func	*ssyn_validate;
	slap_syntax_transform_func	*ssyn_normalize;
	slap_syntax_transform_func	*ssyn_pretty;

#ifdef SLAPD_BINARY_CONVERSION
	/* convert to and from binary */
	slap_syntax_transform_func	*ssyn_ber2str;
	slap_syntax_transform_func	*ssyn_str2ber;
#endif

	struct slap_syntax		*ssyn_next;
} Syntax;

#define slap_syntax_is_flag(s,flag) ((int)((s)->ssyn_flags & (flag)) ? 1 : 0)
#define slap_syntax_is_blob(s)		slap_syntax_is_flag((s),SLAP_SYNTAX_BLOB)
#define slap_syntax_is_binary(s)	slap_syntax_is_flag((s),SLAP_SYNTAX_BINARY)
#define slap_syntax_is_ber(s)		slap_syntax_is_flag((s),SLAP_SYNTAX_BER)
#define slap_syntax_is_hidden(s)	slap_syntax_is_flag((s),SLAP_SYNTAX_HIDE)

/* XXX -> UCS-2 Converter */
typedef int slap_mr_convert_func LDAP_P((
	struct berval * in,
	struct berval ** out ));

/* Normalizer */
typedef int slap_mr_normalize_func LDAP_P((
	unsigned use,
	struct slap_syntax *syntax, /* NULL if in is asserted value */
	struct slap_matching_rule *mr,
	struct berval * in,
	struct berval ** out ));

/* Match (compare) function */
typedef int slap_mr_match_func LDAP_P((
	int *match,
	unsigned use,
	struct slap_syntax *syntax,	/* syntax of stored value */
	struct slap_matching_rule *mr,
	struct berval * value,
	void * assertValue ));

/* Index generation function */
typedef int slap_mr_indexer_func LDAP_P((
	unsigned use,
	struct slap_syntax *syntax,	/* syntax of stored value */
	struct slap_matching_rule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keys ));

/* Filter index function */
typedef int slap_mr_filter_func LDAP_P((
	unsigned use,
	struct slap_syntax *syntax,	/* syntax of stored value */
	struct slap_matching_rule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keys ));

typedef struct slap_matching_rule {
	LDAP_MATCHING_RULE		smr_mrule;
	unsigned				smr_usage;

#define SLAP_MR_TYPE_MASK		0xFF00U
#define SLAP_MR_SUBTYPE_MASK	0x00FFU

#define SLAP_MR_NONE			0x0000U
#define SLAP_MR_EQUALITY		0x0100U
#define SLAP_MR_ORDERING		0x0200U
#define SLAP_MR_SUBSTR			0x0400U
#define SLAP_MR_EXT				0x0800U

#define SLAP_MR_EQUALITY_APPROX	( SLAP_MR_EQUALITY | 0x0001U )

#define SLAP_MR_SUBSTR_INITIAL	( SLAP_MR_SUBSTR | 0x0001U )
#define SLAP_MR_SUBSTR_ANY		( SLAP_MR_SUBSTR | 0x0002U )
#define SLAP_MR_SUBSTR_FINAL	( SLAP_MR_SUBSTR | 0x0004U )

	Syntax					*smr_syntax;
	slap_mr_convert_func	*smr_convert;
	slap_mr_normalize_func	*smr_normalize;
	slap_mr_match_func		*smr_match;
	slap_mr_indexer_func	*smr_indexer;
	slap_mr_filter_func		*smr_filter;
	struct slap_matching_rule	*smr_next;
#define smr_oid				smr_mrule.mr_oid
#define smr_names			smr_mrule.mr_names
#define smr_desc			smr_mrule.mr_desc
#define smr_obsolete		smr_mrule.mr_obsolete
#define smr_syntax_oid		smr_mrule.mr_syntax_oid
#define smr_extensions		smr_mrule.mr_extensions
} MatchingRule;

typedef struct slap_attribute_type {
	char					*sat_cname;
	LDAP_ATTRIBUTE_TYPE		sat_atype;
	struct slap_attribute_type	*sat_sup;
	struct slap_attribute_type	**sat_subtypes;
	MatchingRule			*sat_equality;
	MatchingRule			*sat_approx;
	MatchingRule			*sat_ordering;
	MatchingRule			*sat_substr;
	Syntax				*sat_syntax;
	struct slap_attribute_type	*sat_next;
#define sat_oid			sat_atype.at_oid
#define sat_names		sat_atype.at_names
#define sat_desc		sat_atype.at_desc
#define sat_obsolete		sat_atype.at_obsolete
#define sat_sup_oid		sat_atype.at_sup_oid
#define sat_equality_oid	sat_atype.at_equality_oid
#define sat_ordering_oid	sat_atype.at_ordering_oid
#define sat_substr_oid		sat_atype.at_substr_oid
#define sat_syntax_oid		sat_atype.at_syntax_oid
#define sat_single_value	sat_atype.at_single_value
#define sat_collective		sat_atype.at_collective
#define sat_no_user_mod		sat_atype.at_no_user_mod
#define sat_usage		sat_atype.at_usage
#define sat_extensions		sat_atype.at_extensions
} AttributeType;

#define is_at_operational(at)	((at)->sat_usage)
#define is_at_single_value(at)	((at)->sat_single_value)
#define is_at_collective(at)	((at)->sat_collective)
#define is_at_no_user_mod(at)	((at)->sat_no_user_mod)

typedef struct slap_object_class {
	LDAP_OBJECT_CLASS		soc_oclass;
	struct slap_object_class	**soc_sups;
	AttributeType			**soc_required;
	AttributeType			**soc_allowed;
	struct slap_object_class	*soc_next;
#define soc_oid			soc_oclass.oc_oid
#define soc_names		soc_oclass.oc_names
#define soc_desc		soc_oclass.oc_desc
#define soc_obsolete		soc_oclass.oc_obsolete
#define soc_sup_oids		soc_oclass.oc_sup_oids
#define soc_kind		soc_oclass.oc_kind
#define soc_at_oids_must	soc_oclass.oc_at_oids_must
#define soc_at_oids_may		soc_oclass.oc_at_oids_may
#define soc_extensions		soc_oclass.oc_extensions
} ObjectClass;


/*
 * represents a recognized attribute description ( type + options )
 */
typedef struct slap_attr_desc {
	struct berval *ad_cname;	/* canonical name */
	AttributeType *ad_type;		/* NULL if unknown */
	char *ad_lang;				/* NULL if no language tags */
	unsigned ad_flags;
#define SLAP_DESC_NONE		0x0U
#define SLAP_DESC_BINARY	0x1U
} AttributeDescription;

#define slap_ad_is_lang(ad)		( (ad)->ad_lang != NULL )
#define slap_ad_is_binary(ad)	( (int)((ad)->ad_flags & SLAP_DESC_BINARY) ? 1 : 0 )

/*
 * pointers to schema elements used internally
 */
struct slap_internal_schema {
	/* objectClass */
	ObjectClass *si_oc_top;
	ObjectClass *si_oc_extensibleObject;
	ObjectClass *si_oc_alias;
	ObjectClass *si_oc_referral;
	ObjectClass *si_oc_subentry;
	ObjectClass *si_oc_subschema;
	ObjectClass *si_oc_rootdse;

	/* objectClass attribute */
	AttributeDescription *si_ad_objectClass;

	/* operational attributes */
	AttributeDescription *si_ad_creatorsName;
	AttributeDescription *si_ad_createTimestamp;
	AttributeDescription *si_ad_modifiersName;
	AttributeDescription *si_ad_modifyTimestamp;
	AttributeDescription *si_ad_subschemaSubentry;

	/* root DSE attributes */
	AttributeDescription *si_ad_namingContexts;
	AttributeDescription *si_ad_supportedControl;
	AttributeDescription *si_ad_supportedExtension;
	AttributeDescription *si_ad_supportedLDAPVersion;
	AttributeDescription *si_ad_supportedSASLMechanisms;

	/* subschema subentry attributes */
	AttributeDescription *si_ad_objectClasses;
	AttributeDescription *si_ad_attributeTypes;
	AttributeDescription *si_ad_ldapSyntaxes;
	AttributeDescription *si_ad_matchingRules;
	AttributeDescription *si_ad_matchingRulesUse;

	/* Aliases & Referrals */
	AttributeDescription *si_ad_aliasedObjectName;
	AttributeDescription *si_ad_ref;

	/* Access Control Internals */
	AttributeDescription *si_ad_entry;
	AttributeDescription *si_ad_children;
#ifdef SLAPD_ACI_ENABLED
	AttributeDescription *si_ad_aci;
#endif

	/* Other */
	AttributeDescription *si_ad_userPassword;
	AttributeDescription *si_ad_authPassword;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	AttributeDescription *si_ad_krbName;
#endif
};

typedef struct slap_attr_assertion {
	AttributeDescription	*aa_desc;
	struct berval *aa_value;
} AttributeAssertion;

typedef struct slap_ss_assertion {
	AttributeDescription	*sa_desc;
	struct berval			*sa_initial;
	struct berval			**sa_any;
	struct berval			*sa_final;
} SubstringsAssertion;

typedef struct slap_mr_assertion {
	char					*ma_rule;	/* optional */
	AttributeDescription	*ma_desc;	/* optional */
	int						ma_dnattrs; /* boolean */
	struct berval			*ma_value;	/* required */
} MatchingRuleAssertion;


/*
 * represents a search filter
 */

typedef struct slap_filter {
	ber_tag_t	f_choice;	/* values taken from ldap.h, plus: */
#define SLAPD_FILTER_COMPUTED	((ber_tag_t) -1)
#define SLAPD_FILTER_DN_ONE		((ber_tag_t) -2)
#define SLAPD_FILTER_DN_SUBTREE	((ber_tag_t) -3)


	union f_un_u {
		/* precomputed result */
		ber_int_t f_un_result;

		/* DN */
		char *f_un_dn;

		/* present */
		AttributeDescription *f_un_desc;

		/* simple value assertion */
		AttributeAssertion *f_un_ava;

		/* substring assertion */
		SubstringsAssertion *f_un_ssa;

		/* matching rule assertion */
		MatchingRuleAssertion *f_un_mra;

#define f_dn			f_un.f_un_dn
#define f_desc			f_un.f_un_desc
#define f_ava			f_un.f_un_ava
#define f_av_desc		f_un.f_un_ava->aa_desc
#define f_av_value		f_un.f_un_ava->aa_value
#define f_sub			f_un.f_un_ssa
#define f_sub_desc		f_un.f_un_ssa->sa_desc
#define f_sub_initial	f_un.f_un_ssa->sa_initial
#define f_sub_any		f_un.f_un_ssa->sa_any
#define f_sub_final		f_un.f_un_ssa->sa_final
#define f_mra			f_un.f_un_mra
#define f_mr_rule		f_un.f_un_mra->ma_rule
#define f_mr_desc		f_un.f_un_mra->ma_desc
#define f_mr_value		f_un.f_un_mra->ma_value
#define	f_mr_dnaddrs	f_un.f_un_mra->ma_dnattrs

		/* and, or, not */
		struct slap_filter *f_un_complex;
	} f_un;

#define f_result	f_un.f_un_result
#define f_and		f_un.f_un_complex
#define f_or		f_un.f_un_complex
#define f_not		f_un.f_un_complex
#define f_list		f_un.f_un_complex

	struct slap_filter	*f_next;
} Filter;

/* compare routines can return undefined */
#define SLAPD_COMPARE_UNDEFINED	((ber_tag_t) -1)

/*
 * represents an attribute (description + values)
 */
typedef struct slap_attr {
	AttributeDescription *a_desc;
	struct berval	**a_vals;
	struct slap_attr	*a_next;
} Attribute;


/*
 * the id used in the indexes to refer to an entry
 */
typedef unsigned long	ID;
#define NOID	((ID)~0)

/*
 * represents an entry in core
 */
typedef struct slap_entry {
	/*
	 * The ID field should only be changed before entry is
	 * inserted into a cache.  The ID value is backend
	 * specific.
	 */
	ID		e_id;

	char		*e_dn;		/* DN of this entry */
	char		*e_ndn;		/* normalized DN of this entry */
	Attribute	*e_attrs;	/* list of attributes + values */

	/* for use by the backend for any purpose */
	void*	e_private;
} Entry;

/*
 * A list of LDAPMods
 */
typedef struct slap_mod {
	int sm_op;
	AttributeDescription *sm_desc;
	struct berval **sm_bvalues;
} Modification;

typedef struct slap_mod_list {
	Modification sml_mod;
#define sml_op		sml_mod.sm_op
#define sml_desc	sml_mod.sm_desc
#define sml_bvalues	sml_mod.sm_bvalues
	struct slap_mod_list *sml_next;
} Modifications;

typedef struct slap_ldap_modlist {
	LDAPMod ml_mod;
	struct slap_ldap_modlist *ml_next;
#define ml_op		ml_mod.mod_op
#define ml_type		ml_mod.mod_type
#define ml_values	ml_mod.mod_values
#define ml_bvalues	ml_mod.mod_bvalues
} LDAPModList;

/*
 * represents an access control list
 */

typedef enum slap_access_e {
	ACL_INVALID_ACCESS = -1,
	ACL_NONE = 0,
	ACL_AUTH,
	ACL_COMPARE,
	ACL_SEARCH,
	ACL_READ,
	ACL_WRITE
} slap_access_t;

typedef enum slap_control_e {
	ACL_INVALID_CONTROL	= 0,
	ACL_STOP,
	ACL_CONTINUE,
	ACL_BREAK
} slap_control_t;

typedef unsigned long slap_access_mask_t;

/* the "by" part */
typedef struct slap_access {
	slap_control_t a_type;

#define ACL_ACCESS2PRIV(access)	(0x01U << (access))

#define ACL_PRIV_NONE			ACL_ACCESS2PRIV( ACL_NONE )
#define ACL_PRIV_AUTH			ACL_ACCESS2PRIV( ACL_AUTH )
#define ACL_PRIV_COMPARE		ACL_ACCESS2PRIV( ACL_COMPARE )
#define ACL_PRIV_SEARCH			ACL_ACCESS2PRIV( ACL_SEARCH )
#define ACL_PRIV_READ			ACL_ACCESS2PRIV( ACL_READ )
#define ACL_PRIV_WRITE			ACL_ACCESS2PRIV( ACL_WRITE )

#define ACL_PRIV_MASK			0x00ffUL

/* priv flags */
#define ACL_PRIV_LEVEL			0x1000UL
#define ACL_PRIV_ADDITIVE		0x2000UL
#define ACL_PRIV_SUBSTRACTIVE	0x4000UL

/* invalid privs */
#define ACL_PRIV_INVALID		0x0UL

#define ACL_PRIV_ISSET(m,p)		(((m) & (p)) == (p))
#define ACL_PRIV_ASSIGN(m,p)	do { (m)  =  (p); } while(0)
#define ACL_PRIV_SET(m,p)		do { (m) |=  (p); } while(0)
#define ACL_PRIV_CLR(m,p)		do { (m) &= ~(p); } while(0)

#define ACL_INIT(m)				ACL_PRIV_ASSIGN(m, ACL_PRIV_NONE)
#define ACL_INVALIDATE(m)		ACL_PRIV_ASSIGN(m, ACL_PRIV_INVALID)

#define ACL_GRANT(m,a)			ACL_PRIV_ISSET((m),ACL_ACCESS2PRIV(a))

#define ACL_IS_INVALID(m)		((m) == ACL_PRIV_INVALID)

#define ACL_IS_LEVEL(m)			ACL_PRIV_ISSET((m),ACL_PRIV_LEVEL)
#define ACL_IS_ADDITIVE(m)		ACL_PRIV_ISSET((m),ACL_PRIV_ADDITIVE)
#define ACL_IS_SUBTRACTIVE(m)	ACL_PRIV_ISSET((m),ACL_PRIV_SUBSTRACTIVE)

#define ACL_LVL_NONE			(ACL_PRIV_NONE|ACL_PRIV_LEVEL)
#define ACL_LVL_AUTH			(ACL_PRIV_AUTH|ACL_LVL_NONE)
#define ACL_LVL_COMPARE			(ACL_PRIV_COMPARE|ACL_LVL_AUTH)
#define ACL_LVL_SEARCH			(ACL_PRIV_SEARCH|ACL_LVL_COMPARE)
#define ACL_LVL_READ			(ACL_PRIV_READ|ACL_LVL_SEARCH)
#define ACL_LVL_WRITE			(ACL_PRIV_WRITE|ACL_LVL_READ)

#define ACL_LVL(m,l)			(((m)&ACL_PRIV_MASK) == ((l)&ACL_PRIV_MASK))
#define ACL_LVL_IS_NONE(m)		ACL_LVL((m),ACL_LVL_NONE)
#define ACL_LVL_IS_AUTH(m)		ACL_LVL((m),ACL_LVL_AUTH)
#define ACL_LVL_IS_COMPARE(m)	ACL_LVL((m),ACL_LVL_COMPARE)
#define ACL_LVL_IS_SEARCH(m)	ACL_LVL((m),ACL_LVL_SEARCH)
#define ACL_LVL_IS_READ(m)		ACL_LVL((m),ACL_LVL_READ)
#define ACL_LVL_IS_WRITE(m)		ACL_LVL((m),ACL_LVL_WRITE)

#define ACL_LVL_ASSIGN_NONE(m)		ACL_PRIV_ASSIGN((m),ACL_LVL_NONE)
#define ACL_LVL_ASSIGN_AUTH(m)		ACL_PRIV_ASSIGN((m),ACL_LVL_AUTH)
#define ACL_LVL_ASSIGN_COMPARE(m)	ACL_PRIV_ASSIGN((m),ACL_LVL_COMPARE)
#define ACL_LVL_ASSIGN_SEARCH(m)	ACL_PRIV_ASSIGN((m),ACL_LVL_SEARCH)
#define ACL_LVL_ASSIGN_READ(m)		ACL_PRIV_ASSIGN((m),ACL_LVL_READ)
#define ACL_LVL_ASSIGN_WRITE(m)		ACL_PRIV_ASSIGN((m),ACL_LVL_WRITE)

	slap_access_mask_t	a_mask;

	char		*a_dn_pat;
	AttributeDescription	*a_dn_at;
	int			a_dn_self;

	char		*a_peername_pat;
	char		*a_sockname_pat;

	char		*a_domain_pat;
	char		*a_sockurl_pat;

#ifdef SLAPD_ACI_ENABLED
	AttributeDescription	*a_aci_at;
#endif

	/* ACL Groups */
	char		*a_group_pat;
	ObjectClass				*a_group_oc;
	AttributeDescription	*a_group_at;

	struct slap_access	*a_next;
} Access;

/* the "to" part */
typedef struct slap_acl {
	/* "to" part: the entries this acl applies to */
	Filter		*acl_filter;
	regex_t		acl_dn_re;
	char		*acl_dn_pat;
	char		**acl_attrs;

	/* "by" part: list of who has what access to the entries */
	Access	*acl_access;

	struct slap_acl	*acl_next;
} AccessControl;

/*
 * replog moddn param structure
 */
struct replog_moddn {
	char *newrdn;
	int	deloldrdn;
	char *newsup;
};

/*
 * Backend-info
 * represents a backend 
 */

typedef struct slap_backend_info BackendInfo;	/* per backend type */
typedef struct slap_backend_db BackendDB;		/* per backend database */

LIBSLAPD_F (int) nBackendInfo;
LIBSLAPD_F (int) nBackendDB;
LIBSLAPD_F (BackendInfo	*) backendInfo;
LIBSLAPD_F (BackendDB *) backendDB;

LIBSLAPD_F (int) slapMode;	
#define SLAP_UNDEFINED_MODE	0x0000
#define SLAP_SERVER_MODE	0x0001
#define SLAP_TOOL_MODE		0x0002
#define SLAP_MODE			0x0003

#define SLAP_TRUNCATE_MODE	0x0100
#ifdef SLAPD_BDB2
#define SLAP_TIMED_MODE		0x1000
#endif

/* temporary aliases */
typedef BackendDB Backend;
#define nbackends nBackendDB
#define backends backendDB

struct slap_backend_db {
	BackendInfo	*bd_info;	/* pointer to shared backend info */

	/* BackendInfo accessors */
#define		be_config	bd_info->bi_db_config
#define		be_type		bd_info->bi_type

#define		be_bind		bd_info->bi_op_bind
#define		be_unbind	bd_info->bi_op_unbind
#define		be_add		bd_info->bi_op_add
#define		be_compare	bd_info->bi_op_compare
#define		be_delete	bd_info->bi_op_delete
#define		be_modify	bd_info->bi_op_modify
#define		be_modrdn	bd_info->bi_op_modrdn
#define		be_search	bd_info->bi_op_search

#define		be_extended	bd_info->bi_extended

#define		be_release	bd_info->bi_entry_release_rw
#define		be_group	bd_info->bi_acl_group

#define		be_controls	bd_info->bi_controls

#define		be_connection_init	bd_info->bi_connection_init
#define		be_connection_destroy	bd_info->bi_connection_destroy

#ifdef SLAPD_TOOLS
#define		be_entry_open bd_info->bi_tool_entry_open
#define		be_entry_close bd_info->bi_tool_entry_close
#define		be_entry_first bd_info->bi_tool_entry_first
#define		be_entry_next bd_info->bi_tool_entry_next
#define		be_entry_get bd_info->bi_tool_entry_get
#define		be_entry_put bd_info->bi_tool_entry_put
#define		be_index_attr bd_info->bi_tool_index_attr
#define		be_index_change bd_info->bi_tool_index_change
#define		be_sync bd_info->bi_tool_sync
#endif

#ifdef HAVE_CYRUS_SASL
#define		be_sasl_authorize bd_info->bi_sasl_authorize
#define		be_sasl_getsecret bd_info->bi_sasl_getsecret
#define		be_sasl_putsecret bd_info->bi_sasl_putsecret
#endif

	/* these should be renamed from be_ to bd_ */
	char	**be_suffix;	/* the DN suffixes of data in this backend */
	char	**be_nsuffix;	/* the normalized DN suffixes in this backend */
	char	**be_suffixAlias; /* pairs of DN suffix aliases and deref values */
	char	*be_root_dn;	/* the magic "root" dn for this db 	*/
	char	*be_root_ndn;	/* the magic "root" normalized dn for this db	*/
	struct berval be_root_pw;	/* the magic "root" password for this db	*/
	int	be_readonly;	/* 1 => db is in "read only" mode	   */
	unsigned int be_max_deref_depth;       /* limit for depth of an alias deref  */
	int	be_sizelimit;	/* size limit for this backend   	   */
	int	be_timelimit;	/* time limit for this backend       	   */
	AccessControl *be_acl;	/* access control list for this backend	   */
	slap_access_t	be_dfltaccess;	/* access given if no acl matches	   */
	char	**be_replica;	/* replicas of this backend (in master)	   */
	char	*be_replogfile;	/* replication log file (in master)	   */
	char	*be_update_ndn;	/* allowed to make changes (in replicas) */
	struct berval **be_update_refs;	/* where to refer modifying clients to */
	int	be_lastmod;	/* keep track of lastmodified{by,time}	   */

	char	*be_realm;

	void	*be_private;	/* anything the backend database needs 	   */
};

struct slap_conn;
struct slap_op;

typedef int (*SLAP_EXTENDED_FN) LDAP_P((
    Backend		*be,
    struct slap_conn		*conn,
    struct slap_op		*op,
	const char		*reqoid,
    struct berval * reqdata,
	char		**rspoid,
    struct berval ** rspdata,
	LDAPControl *** rspctrls,
	const char **	text,
	struct berval *** refs ));

struct slap_backend_info {
	char	*bi_type;	/* type of backend */

	/*
	 * per backend type routines:
	 * bi_init: called to allocate a backend_info structure,
	 *		called once BEFORE configuration file is read.
	 *		bi_init() initializes this structure hence is
	 *		called directly from be_initialize()
	 * bi_config: called per 'backend' specific option
	 *		all such options must before any 'database' options
	 *		bi_config() is called only from read_config()
	 * bi_open: called to open each database, called
	 *		once AFTER configuration file is read but
	 *		BEFORE any bi_db_open() calls.
	 *		bi_open() is called from backend_startup()
	 * bi_close: called to close each database, called
	 *		once during shutdown after all bi_db_close calls.
	 *		bi_close() is called from backend_shutdown()
	 * bi_destroy: called to destroy each database, called
	 *		once during shutdown after all bi_db_destroy calls.
	 *		bi_destory() is called from backend_destroy()
	 */
	int (*bi_init)	LDAP_P((BackendInfo *bi));
	int	(*bi_config) LDAP_P((BackendInfo *bi,
		const char *fname, int lineno, int argc, char **argv ));
	int (*bi_open) LDAP_P((BackendInfo *bi));
	int (*bi_close) LDAP_P((BackendInfo *bi));
	int (*bi_destroy) LDAP_P((BackendInfo *bi));

	/*
	 * per database routines:
	 * bi_db_init: called to initialize each database,
	 *	called upon reading 'database <type>' 
	 *	called only from backend_db_init()
	 * bi_db_config: called to configure each database,
	 *  called per database to handle per database options
	 *	called only from read_config()
	 * bi_db_open: called to open each database
	 *	called once per database immediately AFTER bi_open()
	 *	calls but before daemon startup.
	 *  called only by backend_startup()
	 * bi_db_close: called to close each database
	 *	called once per database during shutdown but BEFORE
	 *  any bi_close call.
	 *  called only by backend_shutdown()
	 * bi_db_destroy: called to destroy each database
	 *  called once per database during shutdown AFTER all
	 *  bi_close calls but before bi_destory calls.
	 *  called only by backend_destory()
	 */
	int (*bi_db_init) LDAP_P((Backend *bd));
	int	(*bi_db_config) LDAP_P((Backend *bd,
		const char *fname, int lineno, int argc, char **argv ));
	int (*bi_db_open) LDAP_P((Backend *bd));
	int (*bi_db_close) LDAP_P((Backend *bd));
	int (*bi_db_destroy) LDAP_P((Backend *db));

	/* LDAP Operations Handling Routines */
	int	(*bi_op_bind)  LDAP_P(( BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *dn, const char *ndn, int method,
		struct berval *cred, char** edn ));
	int (*bi_op_unbind) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o ));
	int	(*bi_op_search) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *base, const char *nbase,
		int scope, int deref,
		int slimit, int tlimit,
		Filter *f, const char *filterstr,
		char **attrs, int attrsonly));
	int	(*bi_op_compare)LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *dn, const char *ndn,
		AttributeAssertion *ava));
	int	(*bi_op_modify) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *dn, const char *ndn, Modifications *m));
	int	(*bi_op_modrdn) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *dn, const char *ndn,
		const char *newrdn, int deleteoldrdn,
		const char *newSuperior));
	int	(*bi_op_add)    LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		Entry *e));
	int	(*bi_op_delete) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		const char *dn, const char *ndn));
	int	(*bi_op_abandon) LDAP_P((BackendDB *bd,
		struct slap_conn *c, struct slap_op *o,
		ber_int_t msgid));

	/* Extended Operations Helper */
	SLAP_EXTENDED_FN bi_extended;

	/* Auxilary Functions */
	int	(*bi_entry_release_rw) LDAP_P((BackendDB *bd, Entry *e, int rw));

	int	(*bi_acl_group)  LDAP_P((Backend *bd,
		Entry *e, const char *bdn, const char *edn,
		ObjectClass *group_oc,
		AttributeDescription *group_at ));

	int	(*bi_connection_init) LDAP_P((BackendDB *bd,
		struct slap_conn *c));
	int	(*bi_connection_destroy) LDAP_P((BackendDB *bd,
		struct slap_conn *c));

	/* hooks for slap tools */
	int (*bi_tool_entry_open) LDAP_P(( BackendDB *be, int mode ));
	int (*bi_tool_entry_close) LDAP_P(( BackendDB *be ));
	ID (*bi_tool_entry_first) LDAP_P(( BackendDB *be ));
	ID (*bi_tool_entry_next) LDAP_P(( BackendDB *be ));
	Entry* (*bi_tool_entry_get) LDAP_P(( BackendDB *be, ID id ));
	ID (*bi_tool_entry_put) LDAP_P(( BackendDB *be, Entry *e ));
	int (*bi_tool_index_attr) LDAP_P(( BackendDB *be,
		AttributeDescription *desc ));
	int (*bi_tool_index_change) LDAP_P(( BackendDB *be,
		AttributeDescription *desc,
		struct berval **bv, ID id, int op ));
	int (*bi_tool_sync) LDAP_P(( BackendDB *be ));

#ifdef HAVE_CYRUS_SASL
	int (*bi_sasl_authorize) LDAP_P(( BackendDB *be,
		const char *authnid, const char *authzid,
		const char **canon_authzid, const char **errstr ));
	int (*bi_sasl_getsecret) LDAP_P(( BackendDB *be,
		const char *mechanism, const char *authzid,
		const char *realm, sasl_secret_t **secret ));
	int (*bi_sasl_putsecret) LDAP_P(( BackendDB *be,
		const char *mechanism, const char *auth_identity,
		const char *realm, const sasl_secret_t *secret ));
#endif /* HAVE_CYRUS_SASL */

#define SLAP_INDEX_ADD_OP		0x0001
#define SLAP_INDEX_DELETE_OP	0x0002

	char **bi_controls;		/* supported controls */

	unsigned int bi_nDB;	/* number of databases of this type */
	void	*bi_private;	/* anything the backend type needs */
};

/*
 * represents an operation pending from an ldap client
 */

typedef struct slap_op {
	ber_int_t	o_opid;		/* id of this operation		  */
	ber_int_t	o_msgid;	/* msgid of the request		  */

	ldap_pvt_thread_t	o_tid;		/* thread handling this op	  */

	BerElement	*o_ber;		/* ber of the request		  */

	ber_tag_t	o_tag;		/* tag of the request		  */
	time_t		o_time;		/* time op was initiated	  */

#ifdef SLAP_AUTHZID
	/* should only be used for reporting purposes */
	char	*o_authc_dn;	/* authentication DN */

	/* should be used as the DN of the User */
	char	*o_authz_dn;	/* authorization DN */
	char	*o_authz_ndn;	/* authorizaiton NDN */

#else
	char		*o_dn;		/* dn bound when op was initiated */
	char		*o_ndn;		/* normalized dn bound when op was initiated */
#endif

	ber_int_t	o_protocol;	/* version of the LDAP protocol used by client */
	ber_tag_t	o_authtype;	/* auth method used to bind dn	  */
					/* values taken from ldap.h	  */
					/* LDAP_AUTH_*			  */
	char		*o_authmech; /* SASL mechanism used to bind dn */

	LDAPControl	**o_ctrls;	 /* controls */

	unsigned long	o_connid; /* id of conn initiating this op  */

#ifdef LDAP_CONNECTIONLESS
	int		o_cldap;	/* != 0 if this came in via CLDAP */
	struct sockaddr	o_clientaddr;	/* client address if via CLDAP	  */
	char		o_searchbase;	/* search base if via CLDAP	  */
#endif

	ldap_pvt_thread_mutex_t	o_abandonmutex; /* protects o_abandon  */
	int		o_abandon;	/* abandon flag */

	struct slap_op	*o_next;	/* next operation in list	  */
	void	*o_private;	/* anything the backend needs	  */
} Operation;

/*
 * represents a connection from an ldap client
 */

typedef struct slap_conn {
	int			c_struct_state; /* structure management state */
	int			c_conn_state;	/* connection state */

	ldap_pvt_thread_mutex_t	c_mutex; /* protect the connection */
	Sockbuf		*c_sb;			/* ber connection stuff		  */

	/* only can be changed by connect_init */
	time_t		c_starttime;	/* when the connection was opened */
	time_t		c_activitytime;	/* when the connection was last used */
	unsigned long		c_connid;	/* id of this connection for stats*/

	char		*c_listener_url;	/* listener URL */
	char		*c_peer_domain;	/* DNS name of client */
	char		*c_peer_name;	/* peer name (trans=addr:port) */
	char		*c_sock_name;	/* sock name (trans=addr:port) */

	/* only can be changed by binding thread */
	int		c_sasl_bind_in_progress;	/* multi-op bind in progress */
	char	*c_sasl_bind_mech;			/* mech in progress */
#ifdef HAVE_CYRUS_SASL
	sasl_conn_t	*c_sasl_bind_context;	/* Cyrus SASL state data */
#endif

	/* authentication backend */
	Backend *c_authc_backend;

	/* authorization backend - normally same as c_authc_backend */
	Backend *c_authz_backend;

#ifdef SLAP_AUTHZID
	/* authentication backend */
	/* should only be used for reporting purposes */
	char	*c_authc_dn;	/* authentication DN */

	/* should be used as the DN of the User */
	char	*c_authz_dn;	/* authorization DN */
	char	*c_authz_ndn;	/* authorization NDN */

#else
	char	*c_cdn;		/* DN provided by the client */
	char	*c_dn;		/* DN bound to this conn  */
#endif

	ber_int_t	c_protocol;	/* version of the LDAP protocol used by client */
	ber_tag_t	c_authtype;/* auth method used to bind c_dn  */
	char	*c_authmech;	/* SASL mechanism used to bind c_dn */

	Operation	*c_ops;			/* list of operations being processed */
	Operation	*c_pending_ops;	/* list of pending operations */

	ldap_pvt_thread_mutex_t	c_write_mutex;	/* only one pdu written at a time */
	ldap_pvt_thread_cond_t	c_write_cv;		/* used to wait for sd write-ready*/

	BerElement	*c_currentber;	/* ber we're attempting to read */
	int		c_writewaiter;	/* true if writer is waiting */

#ifdef HAVE_TLS
	int	c_is_tls;		/* true if this LDAP over raw TLS */
	int	c_needs_tls_accept;	/* true if SSL_accept should be called */
#endif

	long	c_n_ops_received;		/* num of ops received (next op_id) */
	long	c_n_ops_executing;	/* num of ops currently executing */
	long	c_n_ops_pending;		/* num of ops pending execution */
	long	c_n_ops_completed;	/* num of ops completed */

	long	c_n_get;		/* num of get calls */
	long	c_n_read;		/* num of read calls */
	long	c_n_write;		/* num of write calls */
} Connection;

#if defined(LDAP_SYSLOG) && defined(LDAP_DEBUG)
#define Statslog( level, fmt, connid, opid, arg1, arg2, arg3 )	\
	do { \
		if ( ldap_debug & (level) ) \
			fprintf( stderr, (fmt), (connid), (opid), (arg1), (arg2), (arg3) );\
		if ( ldap_syslog & (level) ) \
			syslog( ldap_syslog_level, (fmt), (connid), (opid), (arg1), \
			        (arg2), (arg3) ); \
	} while (0)
#else
#define Statslog( level, fmt, connid, opid, arg1, arg2, arg3 )
#endif

LDAP_END_DECL

#include "proto-slap.h"

#endif /* _SLAP_H_ */

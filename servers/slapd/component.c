/* component.c -- Component Filter Match Routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Portions Copyright 2004 by IBM Corporation.
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

#include <ac/string.h>
#include <ac/socket.h>

#include "lutil.h"
#include <ldap.h>
#include "slap.h"

#ifdef LDAP_COMP_MATCH

#include "component.h"

/*
 * This three function pointers are initialized
 * when a component module is loaded
 */
convert_attr_to_comp_func* attr_converter = NULL ;
convert_assert_to_comp_func* assert_converter = NULL ;
convert_asn_to_ldap_func* csi_converter = NULL ;
free_component_func* component_destructor = NULL ;

#define OID_ALL_COMP_MATCH "1.2.36.79672281.1.13.6"
#define OID_COMP_FILTER_MATCH "1.2.36.79672281.1.13.2"
#define MAX_LDAP_STR_LEN 128

static int
peek_componentId_type( ComponentAssertionValue* cav );

static int
strip_cav_str( ComponentAssertionValue* cav, char* str);

static int
peek_cav_str( ComponentAssertionValue* cav, char* str );

static int
parse_comp_filter( Operation* op, ComponentAssertionValue* cav,
				ComponentFilter** filt, const char** text );

static void
free_comp_filter( ComponentFilter* f );

static int
test_comp_filter( Syntax *syn, Attribute	*a, struct berval *bv,
			ComponentFilter *f );

int
componentCertificateValidate(
	Syntax *syntax,
	struct berval *val )
{
	return LDAP_SUCCESS;
}

int
componentFilterValidate(
	Syntax *syntax,
	struct berval *val )
{
	return LDAP_SUCCESS;
}

int
allComponentsValidate(
	Syntax *syntax,
	struct berval *val )
{
	return LDAP_SUCCESS;
}

int
componentFilterMatch ( 
	int *matchp, 
	slap_mask_t flags, 
	Syntax *syntax, 
	MatchingRule *mr,
	struct berval *value, 
	void *assertedValue )
{
	Attribute *a = (Attribute*)value;
	MatchingRuleAssertion * ma = (MatchingRuleAssertion*)assertedValue;

	int rc;

	if ( !(mr && mr->smr_usage & SLAP_MR_COMPONENT) || !ma->ma_cf )
		return LDAP_INAPPROPRIATE_MATCHING;
		
	rc = test_comp_filter( syntax, a, a->a_vals, ma->ma_cf );
	if ( component_destructor && a->a_component_values ) {
		component_destructor(a->a_component_values);
		a->a_component_values = NULL;
	}
	if ( rc == LDAP_COMPARE_TRUE ) {
		*matchp = 0;
		return LDAP_SUCCESS;
	}
	else if ( rc == LDAP_COMPARE_FALSE ) {
		*matchp = 1;
		return LDAP_SUCCESS;
	}
	else {
		return LDAP_INAPPROPRIATE_MATCHING;
	}
	
}

int
allComponentsMatch( 
	int *matchp, 
	slap_mask_t flags, 
	Syntax *syntax, 
	MatchingRule *mr,
	struct berval *value, 
	void *assertedValue )
{
	/* Only for Registeration */
	*matchp = 0;
	return LDAP_SUCCESS;
}

static int
slapd_ber2cav( struct berval* bv, ComponentAssertionValue* cav)
{
	int len;

	len = ldap_pvt_filter_value_unescape( bv->bv_val );
	if ( len == -1 ) {
		return LDAP_FILTER_ERROR;
	}
	cav->cav_ptr = cav->cav_buf = bv->bv_val;
	cav->cav_end = bv->bv_val + len;

	return LDAP_SUCCESS;
}

int
get_comp_filter( Operation* op, struct berval* bv, ComponentFilter** filt,
		 const char **text )
{
	ComponentAssertionValue cav;
	int rc;

	Debug( LDAP_DEBUG_FILTER, "get_comp_filter\n", 0, 0, 0 );
	if ( (rc = slapd_ber2cav(bv, &cav) ) != LDAP_SUCCESS ) {
		return rc;
	}
	rc = parse_comp_filter( op, &cav, filt, text );
	bv->bv_val = cav.cav_ptr;

	return rc;
}

static void
eat_whsp( ComponentAssertionValue* cav )
{
	for ( ; ( *cav->cav_ptr == ' ' ) && ( cav->cav_ptr < cav->cav_end ) ; ) {
		cav->cav_ptr++;
	}
}

static int
cav_cur_len( ComponentAssertionValue* cav )
{
	return cav->cav_end - cav->cav_ptr;
}

static ber_tag_t
comp_first_element( ComponentAssertionValue* cav )
{
	eat_whsp( cav );
	if ( cav_cur_len( cav ) >= 8 && strncmp( cav->cav_ptr, "item", 4 ) == 0 ) {
		return LDAP_COMP_FILTER_ITEM;
	}
	else if ( cav_cur_len( cav ) >= 7 && strncmp( cav->cav_ptr, "and", 3 ) == 0 ) {
		return LDAP_COMP_FILTER_AND;
	}
	else if ( cav_cur_len( cav ) >= 6 && strncmp( cav->cav_ptr, "or" , 2 ) == 0 ) {
		return LDAP_COMP_FILTER_OR;
	}
	else if ( cav_cur_len( cav ) >= 7 && strncmp( cav->cav_ptr, "not", 3 ) == 0 ) {
		return LDAP_COMP_FILTER_NOT;
	}
	else
		return LDAP_COMP_FILTER_UNDEFINED;
}

static ber_tag_t
comp_next_element( ComponentAssertionValue* cav )
{

	eat_whsp( cav );
	if ( *(cav->cav_ptr) == ',' ) {
		/* move pointer to the next CA */
		cav->cav_ptr++;
		return comp_first_element( cav );
	}
	else return LDAP_COMP_FILTER_UNDEFINED;
}

static int
get_comp_filter_list( Operation *op, ComponentAssertionValue *cav,
			ComponentFilter** f, const char** text )
{
	ComponentFilter **new;
	int		err;
	ber_tag_t	tag;

	Debug( LDAP_DEBUG_FILTER, "get_comp_filter_list\n", 0, 0, 0 );
	new = f;
	for ( tag = comp_first_element( cav ); tag != LDAP_COMP_FILTER_UNDEFINED;
		tag = comp_next_element( cav ) )
	{
		err = parse_comp_filter( op, cav, new, text );
		if ( err != LDAP_SUCCESS )
			return ( err );
		new = &(*new)->cf_next;
	}
	*new = NULL;

	return( LDAP_SUCCESS );
}

static int
get_componentId( Operation *op, ComponentAssertionValue* cav,
			ComponentId ** cid, const char** text )
{
	ber_tag_t type;
	ComponentId _cid;
	int len;

	type = peek_componentId_type( cav );

	Debug( LDAP_DEBUG_FILTER, "get_compId [%d]\n", type, 0, 0 );
	len = 0;
	_cid.ci_type = type;
	_cid.ci_next = NULL;
	switch ( type ) {
	case LDAP_COMPREF_IDENTIFIER :
		_cid.ci_val.ci_identifier.bv_val = cav->cav_ptr;
		for( ;cav->cav_ptr[len] != ' ' && cav->cav_ptr[len] != '\0' &&
			cav->cav_ptr[len] != '.' && cav->cav_ptr[len] != '\"' ; len++ );
		_cid.ci_val.ci_identifier.bv_len = len;
		cav->cav_ptr += len;
		break;
	case LDAP_COMPREF_FROM_BEGINNING :
		for( ;cav->cav_ptr[len] != ' ' && cav->cav_ptr[len] != '\0' &&
			cav->cav_ptr[len] != '.' && cav->cav_ptr[len] != '\"' ; len++ );
		_cid.ci_val.ci_from_beginning = strtol( cav->cav_ptr, NULL, 0 );
		cav->cav_ptr += len;
		break;
	case LDAP_COMPREF_FROM_END :
		for( ;cav->cav_ptr[len] != ' ' && cav->cav_ptr[len] != '\0' &&
			cav->cav_ptr[len] != '.' && cav->cav_ptr[len] != '\"' ; len++ );
		_cid.ci_val.ci_from_end = strtol( cav->cav_ptr, NULL, 0 );
		cav->cav_ptr += len;
		break;
	case LDAP_COMPREF_COUNT :
		_cid.ci_val.ci_count = 0;
		cav->cav_ptr++;
		break;
	case LDAP_COMPREF_CONTENT :
		/* FIXEME: yet to be implemented */
		break;
	case LDAP_COMPREF_SELECT :
		/* FIXEME: yet to be implemented */
		break;
	case LDAP_COMPREF_ALL :
		_cid.ci_val.ci_all = '*';
		cav->cav_ptr++;
	Debug( LDAP_DEBUG_FILTER, "get_compId : ALL\n", 0, 0, 0 );
		break;
	default :
		return LDAP_COMPREF_UNDEFINED;
	}

	*cid = op->o_tmpalloc( sizeof( ComponentId ), op->o_tmpmemctx );
	**cid = _cid;
	return LDAP_SUCCESS;
}

static int
peek_componentId_type( ComponentAssertionValue* cav )
{
	eat_whsp( cav );
	if ( cav->cav_ptr[0] == '-' )
		return LDAP_COMPREF_FROM_END;
	else if ( cav->cav_ptr[0] == '(' )
		return LDAP_COMPREF_SELECT;
	else if ( cav->cav_ptr[0] == '*' )
		return LDAP_COMPREF_ALL;
	else if ( cav->cav_ptr[0] == '0' )
		return LDAP_COMPREF_COUNT;
	else if ( cav->cav_ptr[0] > '0' && cav->cav_ptr[0] <= '9' )
		return LDAP_COMPREF_FROM_BEGINNING;
	else if ( (cav->cav_end - cav->cav_ptr) >= 7 &&
		strncmp(cav->cav_ptr,"content",7) == 0 )
		return LDAP_COMPREF_CONTENT;
	else if ( (cav->cav_ptr[0] >= 'a' && cav->cav_ptr[0] <= 'z') ||
			(cav->cav_ptr[0] >= 'A' && cav->cav_ptr[0] <= 'Z') )
		 
		return LDAP_COMPREF_IDENTIFIER;
	else
		return LDAP_COMPREF_UNDEFINED;
}

static ber_tag_t
comp_next_id( ComponentAssertionValue* cav )
{

	if ( *(cav->cav_ptr) == '.' ) {
		cav->cav_ptr++;
		return LDAP_COMPREF_DEFINED;
	}
	else return LDAP_COMPREF_UNDEFINED;
}

static int
get_component_reference( Operation *op, ComponentAssertionValue* cav,
			ComponentReference** cr, const char** text )
{
	int rc,count=0;
	ber_int_t type;
	ComponentReference* ca_comp_ref;
	ComponentId** cr_list;

	eat_whsp( cav );
	ca_comp_ref =
		op->o_tmpalloc( sizeof( ComponentReference ), op->o_tmpmemctx );

	cr_list = &ca_comp_ref->cr_list;
	strip_cav_str( cav, "\"");
	for ( type = peek_componentId_type( cav ) ; type != LDAP_COMPREF_UNDEFINED
		; type = comp_next_id( cav ), count++ ) {
		rc = get_componentId( op, cav, cr_list, text );
		if ( rc == LDAP_SUCCESS ) {
			if ( count == 0 ) ca_comp_ref->cr_curr = ca_comp_ref->cr_list;
			cr_list = &(*cr_list)->ci_next;
		}
		else if ( rc == LDAP_COMPREF_UNDEFINED )
			return rc;
	}
	ca_comp_ref->cr_len = count;
	strip_cav_str( cav, "\"");

	if ( rc == LDAP_SUCCESS ) {	
		*cr = ca_comp_ref;
		**cr = *ca_comp_ref;	
	}
	else op->o_tmpfree( ca_comp_ref , op->o_tmpmemctx );

	return rc;
}

static int
get_ca_use_default( Operation *op, ComponentAssertionValue* cav,
		int* ca_use_def, const char**  text )
{
	if ( peek_cav_str( cav, "useDefaultValues" ) == LDAP_SUCCESS ) {
		strip_cav_str( cav, "useDefaultValues" );
		if ( peek_cav_str( cav, "TRUE" ) == LDAP_SUCCESS ) {
			strip_cav_str( cav, "TRUE" );
			*ca_use_def = 1;
		} else if ( peek_cav_str( cav, "FALSE" ) == LDAP_SUCCESS ) {
			strip_cav_str( cav, "FALSE" );
			*ca_use_def = 0;
		} else {
			return LDAP_INVALID_SYNTAX;
		}

	} else {
		/* If not defined, default value is TRUE */
		*ca_use_def = 1;
	}

	return LDAP_SUCCESS;
}

static int
get_matching_rule( Operation *op, ComponentAssertionValue* cav,
		MatchingRule** mr, const char**  text )
{
	int count = 0;
	struct berval rule_text = { 0L, NULL };

	eat_whsp( cav );

	for ( ; ; count++ ) {
		if ( cav->cav_ptr[count] == ' ' || cav->cav_ptr[count] == ',' ||
			cav->cav_ptr[count] == '\0' || cav->cav_ptr[count] == '{' ||
			cav->cav_ptr[count] == '}' || cav->cav_ptr[count] == '\n' )
			break;
	}

	if ( count == 0 ) {
		*text = "component matching rule not recognized";
		return LDAP_INAPPROPRIATE_MATCHING;
	}
	
	rule_text.bv_len = count;
	rule_text.bv_val = cav->cav_ptr;
	*mr = mr_bvfind( &rule_text );
	cav->cav_ptr += count;
	Debug( LDAP_DEBUG_FILTER, "get_matching_rule: %s\n", (*mr)->smr_mrule.mr_oid, 0, 0 );
	if ( *mr == NULL ) {
		*text = "component matching rule not recognized";
		return LDAP_INAPPROPRIATE_MATCHING;
	}
	return LDAP_SUCCESS;
}

static int
get_GSER_value( ComponentAssertionValue* cav, struct berval* bv )
{
	int count, sequent_dquote, unclosed_brace, succeed;

	eat_whsp( cav );
	/*
	 * Four cases of GSER <Values>
	 * 1) "..." :
	 *	StringVal, GeneralizedTimeVal, UTCTimeVal, ObjectDescriptorVal
	 * 2) '...'B or '...'H :
	 *	BitStringVal, OctetStringVal
	 * 3) {...} :
	 *	SEQUENCE, SEQUENCEOF, SETOF, SET, CHOICE
	 * 4) Between two white spaces
	 *	INTEGER, BOOLEAN, NULL,ENUMERATE, etc
	 */

	succeed = 0;
	if ( cav->cav_ptr[0] == '"' ) {
		for( count = 1, sequent_dquote = 0 ; ; count++ ) {
			/* In order to find escaped double quote */
			if ( cav->cav_ptr[count] == '"' ) sequent_dquote++;
			else sequent_dquote = 0;

			if ( cav->cav_ptr[count] == '\0' || cav->cav_ptr > cav->cav_end ) {
				break;
			}
				
			if ( ( cav->cav_ptr[count] == '"' && cav->cav_ptr[count-1] != '"') ||
			( sequent_dquote > 2 && (sequent_dquote%2) == 1 ) ) {
				succeed = 1;
				break;
			}
		}
	}
	else if ( cav->cav_ptr[0] == '\'' ) {
		for( count = 1 ; ; count++ ) {
			if ( cav->cav_ptr[count] == '\0' || cav->cav_ptr > cav->cav_end ) {
				break;
			}
			if ((cav->cav_ptr[count-1] == '\'' && cav->cav_ptr[count] == 'B')||
			(cav->cav_ptr[count-1] == '\'' && cav->cav_ptr[count] == 'H') ) {
				succeed = 1;
				break;
			}
		}
				
	}
	else if ( cav->cav_ptr[0] == '{' ) {
		for( count = 1, unclosed_brace = 1 ; ; count++ ) {
			if ( cav->cav_ptr[count] == '{' ) unclosed_brace++;
			if ( cav->cav_ptr[count] == '}' ) unclosed_brace--;

			if ( cav->cav_ptr[count] == '\0' || cav->cav_ptr > cav->cav_end )
				break;
			if ( unclosed_brace == 0 ) {
				succeed = 1;
				break;
			}
		}
	}
	else {
		succeed = 1;
		count = cav->cav_end - cav->cav_ptr;
	}

	if ( !succeed ) return LDAP_FILTER_ERROR;

	bv->bv_val = cav->cav_ptr;
	bv->bv_len = count + 1 ;
	cav->cav_ptr += count;
	return LDAP_SUCCESS;
}

static int
get_matching_value( Operation *op, ComponentAssertion* ca,
		 	ComponentAssertionValue* cav, struct berval* bv,
			const char**  text )
{
	if ( !(ca->ca_ma_rule->smr_usage & (SLAP_MR_COMPONENT)) ) {
		if ( get_GSER_value( cav, bv ) != LDAP_SUCCESS ) {
			return LDAP_FILTER_ERROR;
		}

	} else {
		/* embeded componentFilterMatch Description */
		bv->bv_val = cav->cav_ptr;
		bv->bv_len = cav_cur_len( cav );
	}

	return LDAP_SUCCESS;
}

/* Don't move the position pointer, just peek given string */
static int
peek_cav_str( ComponentAssertionValue* cav, char* str )
{
	eat_whsp( cav );
	if ( cav_cur_len( cav ) >= strlen( str ) &&
		strncmp( cav->cav_ptr, str, strlen( str ) ) == 0 )
		return LDAP_SUCCESS;
	else 
		return LDAP_INVALID_SYNTAX;
}

static int
strip_cav_str( ComponentAssertionValue* cav, char* str)
{
	eat_whsp( cav );
	if ( cav_cur_len( cav ) >= strlen( str ) &&
		strncmp( cav->cav_ptr, str, strlen( str ) ) == 0 ) {
		cav->cav_ptr += strlen( str );
		return LDAP_SUCCESS;
	}
	else 
		return LDAP_INVALID_SYNTAX;
}

/*
 * TAG : "item", "and", "or", "not"
 */
static int
strip_cav_tag( ComponentAssertionValue* cav )
{

	eat_whsp( cav );
	if ( cav_cur_len( cav ) >= 8 && strncmp( cav->cav_ptr, "item", 4 ) == 0 ) {
		strip_cav_str( cav , "item:" );
		return LDAP_COMP_FILTER_ITEM;
	}
	else if ( cav_cur_len( cav ) >= 7 && strncmp( cav->cav_ptr, "and", 3 ) == 0 ) {
		strip_cav_str( cav , "and:" );
		return LDAP_COMP_FILTER_AND;
	}
	else if ( cav_cur_len( cav ) >= 6 && strncmp( cav->cav_ptr, "or" , 2 ) == 0 ) {
		strip_cav_str( cav , "or:" );
		return LDAP_COMP_FILTER_OR;
	}
	else if ( cav_cur_len( cav ) >= 7 && strncmp( cav->cav_ptr, "not", 3 ) == 0 ) {
		strip_cav_str( cav , "not:" );
		return LDAP_COMP_FILTER_NOT;
	}
	else
		return LBER_ERROR;
}

/*
 * when encoding, "item" is denotation of ComponentAssertion
 * ComponentAssertion :: SEQUENCE {
 *	component		ComponentReference (SIZE(1..MAX)) OPTIONAL,
 *	useDefaultValues	BOOLEAN DEFAULT TRUE,
 *	rule			MATCHING-RULE.&id,
 *	value			MATCHING-RULE.&AssertionType }
 */
static int
get_item( Operation *op, ComponentAssertionValue* cav, ComponentAssertion** ca,
		const char** text )
{
	int rc;
	ComponentAssertion* _ca;

	Debug( LDAP_DEBUG_FILTER, "get_item: %s\n", 0, 0, 0 );
	_ca = op->o_tmpalloc( sizeof( ComponentAssertion ), op->o_tmpmemctx );

	_ca->ca_component_values = NULL;

	rc = peek_cav_str( cav, "component" );
	if ( rc == LDAP_SUCCESS ) {
		strip_cav_str( cav, "component" );
		rc = get_component_reference( op, cav, &_ca->ca_comp_ref, text );
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_INVALID_SYNTAX;
			op->o_tmpfree( _ca, op->o_tmpmemctx );
			return rc;
		}
	}

	strip_cav_str( cav,",");
	rc = peek_cav_str( cav, "useDefaultValues");
	if ( rc == LDAP_SUCCESS ) {
		rc = get_ca_use_default( op, cav, &_ca->ca_use_def, text );
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_INVALID_SYNTAX;
			op->o_tmpfree( _ca, op->o_tmpmemctx );
			return rc;
		}
		strip_cav_str( cav,",");
	}

	if ( !( strip_cav_str( cav, "rule" ) == LDAP_SUCCESS &&
		get_matching_rule( op, cav , &_ca->ca_ma_rule, text ) == LDAP_SUCCESS )) {
		rc = LDAP_INAPPROPRIATE_MATCHING;
		op->o_tmpfree( _ca, op->o_tmpmemctx );
		return rc;
	}
	
	strip_cav_str( cav,",");
	if ( !(strip_cav_str( cav, "value" ) == LDAP_SUCCESS &&
		get_matching_value( op, _ca, cav, &_ca->ca_ma_value,text ) == LDAP_SUCCESS )) {
		rc = LDAP_INVALID_SYNTAX;
		op->o_tmpfree( _ca, op->o_tmpmemctx );
		return rc;
	}

	/* componentFilterMatch contains componentFilterMatch in it */
	if ( strcmp(_ca->ca_ma_rule->smr_mrule.mr_oid, OID_COMP_FILTER_MATCH ) == 0) {
		struct berval bv;
		bv.bv_val = cav->cav_ptr;
		bv.bv_len = cav_cur_len( cav );
		rc = get_comp_filter( op, &bv,(ComponentFilter**)&_ca->ca_cf, text );
		if ( rc != LDAP_SUCCESS ) {
			op->o_tmpfree( _ca, op->o_tmpmemctx );
			return rc;
		}
		cav->cav_ptr = bv.bv_val;
		assert( cav->cav_end >= bv.bv_val );
	}

	*ca = _ca;
	return LDAP_SUCCESS;
}

static int
parse_comp_filter( Operation* op, ComponentAssertionValue* cav,
				ComponentFilter** filt, const char** text )
{
	/*
	 * A component filter looks like this coming in:
	 *	Filter ::= CHOICE {
	 *		item	[0]	ComponentAssertion,
	 *		and	[1]	SEQUENCE OF ComponentFilter,
	 *		or	[2]	SEQUENCE OF ComponentFilter,
	 *		not	[3]	ComponentFilter,
	 *	}
	 */

	ber_tag_t	tag;
	int		err;
	ComponentFilter	f;
	/* TAG : item, and, or, not in RFC 2254 */
	tag = strip_cav_tag( cav );

	if ( tag == LBER_ERROR ) {
		*text = "error decoding comp filter";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( tag != LDAP_COMP_FILTER_NOT )
		strip_cav_str( cav, "{");

	err = LDAP_SUCCESS;

	f.cf_next = NULL;
	f.cf_choice = tag; 

	switch ( f.cf_choice ) {
	case LDAP_COMP_FILTER_AND:
	Debug( LDAP_DEBUG_FILTER, "LDAP_COMP_FILTER_AND\n", 0, 0, 0 );
		err = get_comp_filter_list( op, cav, &f.cf_and, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		if ( f.cf_and == NULL ) {
			f.cf_choice = SLAPD_FILTER_COMPUTED;
			f.cf_result = LDAP_COMPARE_TRUE;
		}
		break;

	case LDAP_COMP_FILTER_OR:
	Debug( LDAP_DEBUG_FILTER, "LDAP_COMP_FILTER_OR\n", 0, 0, 0 );
		err = get_comp_filter_list( op, cav, &f.cf_or, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		if ( f.cf_or == NULL ) {
			f.cf_choice = SLAPD_FILTER_COMPUTED;
			f.cf_result = LDAP_COMPARE_FALSE;
		}
		/* no assert - list could be empty */
		break;

	case LDAP_COMP_FILTER_NOT:
	Debug( LDAP_DEBUG_FILTER, "LDAP_COMP_FILTER_NOT\n", 0, 0, 0 );
		err = parse_comp_filter( op, cav, &f.cf_not, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f.cf_not != NULL );
		if ( f.cf_not->cf_choice == SLAPD_FILTER_COMPUTED ) {
			int fresult = f.cf_not->cf_result;
			f.cf_choice = SLAPD_FILTER_COMPUTED;
			op->o_tmpfree( f.cf_not, op->o_tmpmemctx );
			f.cf_not = NULL;

			switch ( fresult ) {
			case LDAP_COMPARE_TRUE:
				f.cf_result = LDAP_COMPARE_FALSE;
				break;
			case LDAP_COMPARE_FALSE:
				f.cf_result = LDAP_COMPARE_TRUE;
				break;
			default: ;
				/* (!Undefined) is Undefined */
			}
		}
		break;

	case LDAP_COMP_FILTER_ITEM:
	Debug( LDAP_DEBUG_FILTER, "LDAP_COMP_FILTER_ITEM\n", 0, 0, 0 );
		err = get_item( op, cav, &f.cf_ca, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f.cf_ca != NULL );
		break;

	default:
		f.cf_choice = SLAPD_FILTER_COMPUTED;
		f.cf_result = SLAPD_COMPARE_UNDEFINED;
		break;
	}

	if ( tag != LDAP_COMP_FILTER_NOT )
		strip_cav_str( cav, "}");

	if ( err != LDAP_SUCCESS && err != SLAPD_DISCONNECT ) {
		*text = NULL;
		f.cf_choice = SLAPD_FILTER_COMPUTED;
		f.cf_result = SLAPD_COMPARE_UNDEFINED;
		err = LDAP_SUCCESS;
	}

	if ( err == LDAP_SUCCESS ) {
		*filt = op->o_tmpalloc( sizeof(f), op->o_tmpmemctx );
		**filt = f;
	}

	return( err );
}

static int
test_comp_filter_and(
	Syntax *syn,
	Attribute *a,
	struct berval  *bv,
	ComponentFilter *flist )
{
	ComponentFilter *f;
	int rtn = LDAP_COMPARE_TRUE;

	for ( f = flist ; f != NULL; f = f->cf_next ) {
		int rc = test_comp_filter( syn, a, bv, f );
		if ( rc == LDAP_COMPARE_FALSE ) {
			rtn = rc;
			break;
		}
	
		if ( rc != LDAP_COMPARE_TRUE ) {
			rtn = rc;
		}
	}

	return rtn;
}

static int
test_comp_filter_or(
	Syntax *syn,
	Attribute *a,
	struct berval	  *bv,
	ComponentFilter *flist )
{
	ComponentFilter *f;
	int rtn = LDAP_COMPARE_TRUE;

	for ( f = flist ; f != NULL; f = f->cf_next ) {
		int rc = test_comp_filter( syn, a, bv, f );
		if ( rc == LDAP_COMPARE_TRUE ) {
			rtn = rc;
			break;
		}
	
		if ( rc != LDAP_COMPARE_FALSE ) {
			rtn = rc;
		}
	}

	return rtn;
}

static int
csi_value_match( MatchingRule *mr, struct berval* bv_attr,
		struct berval* bv_assert )
{
	int rc;
	int match;

	assert( mr != NULL );
	assert( !(mr->smr_usage & SLAP_MR_COMPONENT) );

	if( !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	rc = (mr->smr_match)( &match, 0, NULL /*ad->ad_type->sat_syntax*/,
				mr, bv_attr, bv_assert );
	if ( rc == LDAP_SUCCESS )
		return match? LDAP_COMPARE_FALSE:LDAP_COMPARE_TRUE;
	else
		return rc;
}

int
component_value_match( MatchingRule* mr,
	ComponentSyntaxInfo* csi_attr, ComponentSyntaxInfo* csi_assert )
{
	if ( mr->smr_usage & SLAP_MR_COMPONENT ){
		if ( strcmp( mr->smr_mrule.mr_oid, OID_ALL_COMP_MATCH ) == 0 )
		{
			/* allComponentMatch */
			return csi_attr->csi_comp_desc->cd_all_match( NULL,
						csi_attr, csi_assert );
		} else {
			return csi_assert->csi_comp_desc->cd_all_match(
				mr->smr_mrule.mr_oid, csi_attr, csi_assert );
		}

	} else {
		if ( csi_attr->csi_comp_desc->cd_type == ASN_BASIC ) {
			struct berval bv1, bv2;
			char attr_buf[MAX_LDAP_STR_LEN],assert_buf[MAX_LDAP_STR_LEN];
			bv1.bv_val = attr_buf;
			bv2.bv_val = assert_buf;
			if ( csi_converter &&
				( csi_converter ( csi_attr, &bv1 ) == LDAP_SUCCESS ) &&
				( csi_converter ( csi_assert, &bv2 ) == LDAP_SUCCESS ) )
			{
				return csi_value_match( mr, &bv1, &bv2 );

			} else {
				return LDAP_INAPPROPRIATE_MATCHING;
			}

		} else if ( csi_attr->csi_comp_desc->cd_type == ASN_COMPOSITE )
		{
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	/* FIXME: what should be returned here? Is this rachable at all? */
	return LDAP_INAPPROPRIATE_MATCHING;
}

/*
 * return codes : LDAP_COMPARE_TRUE, LDAP_COMPARE_FALSE
 */

static int
test_comp_filter_item(
	Syntax *syn,
	Attribute	*a,
	struct berval	*bv,
	ComponentAssertion *ca )
{
	int rc, len;
	ComponentSyntaxInfo* csi_attr, *csi_assert=NULL;

	if ( strcmp(ca->ca_ma_rule->smr_mrule.mr_oid,
		OID_COMP_FILTER_MATCH ) == 0 && ca->ca_cf ) {
		/* componentFilterMatch inside of componentFilterMatch */
		rc = test_comp_filter( syn, a, bv, ca->ca_cf );
		return rc;
	}

	/* load attribute containg components */
	/* For a testing purpose, link following function here */
	if ( !a->a_component_values && attr_converter )
		a->a_component_values = attr_converter (a, syn, bv);

	if ( a->a_component_values == NULL )
		return LDAP_PROTOCOL_ERROR;

	/* load component containg the referenced component */
	ca->ca_comp_ref->cr_curr = ca->ca_comp_ref->cr_list;
	csi_attr = (((ComponentSyntaxInfo*)a->a_component_values)->csi_comp_desc->cd_extract_i)( ca->ca_comp_ref, a->a_component_values );

	if ( !csi_attr )
		return LDAP_PROTOCOL_ERROR;

	/* decode the asserted value */
	if( !ca->ca_component_values && assert_converter ) {
		assert_converter ( csi_attr, &ca->ca_ma_value,
					&csi_assert, &len, DEC_ALLOC_MODE_0 );
		ca->ca_component_values = (void*)csi_assert;
	}
	else csi_assert = ca->ca_component_values;

	if ( !csi_assert )
		return LDAP_PROTOCOL_ERROR;

	return component_value_match( ca->ca_ma_rule, csi_attr, csi_assert);
}

static int
test_comp_filter(
    Syntax *syn,
    Attribute	*a,
    struct berval *bv,
    ComponentFilter *f )
{
	int	rc;

	if ( !f ) return LDAP_PROTOCOL_ERROR;

	Debug( LDAP_DEBUG_FILTER, "test_comp_filter\n", 0, 0, 0 );
	switch ( f->cf_choice ) {
	case SLAPD_FILTER_COMPUTED:
		rc = f->cf_result;
		break;
	case LDAP_COMP_FILTER_AND:
		rc = test_comp_filter_and( syn, a, bv, f->cf_and );
		break;
	case LDAP_COMP_FILTER_OR:
		rc = test_comp_filter_or( syn, a, bv, f->cf_or );
		break;
	case LDAP_COMP_FILTER_NOT:
		rc = test_comp_filter( syn, a, bv, f->cf_not );

		switch ( rc ) {
		case LDAP_COMPARE_TRUE:
			rc = LDAP_COMPARE_FALSE;
			break;
		case LDAP_COMPARE_FALSE:
			rc = LDAP_COMPARE_TRUE;
			break;
		}
		break;
	case LDAP_COMP_FILTER_ITEM:
		rc = test_comp_filter_item( syn, a, bv, f->cf_ca );
		break;
	default:
		rc = LDAP_PROTOCOL_ERROR;
	}

	return( rc );
}

static void
free_comp_filter_list( ComponentFilter* f )
{
	ComponentFilter* tmp;
	for ( tmp = f ; tmp; tmp = tmp->cf_next );
	{
		free_comp_filter( tmp );
	}
}

static void
free_comp_filter( ComponentFilter* f )
{
	switch ( f->cf_choice ) {
	case LDAP_COMP_FILTER_AND:
	case LDAP_COMP_FILTER_OR:
	case LDAP_COMP_FILTER_NOT:
		free_comp_filter( f->cf_any );
		break;

	case LDAP_COMP_FILTER_ITEM:
		if ( component_destructor && f->cf_ca->ca_component_values )
			component_destructor( f->cf_ca->ca_component_values );
		break;

	default:
		break;
	}
}

void
component_free( ComponentFilter *f ) {
	free_comp_filter( f );
}

#endif

/* Copyright 2004 IBM Corporation
 * All rights reserved.
 * Redisribution and use in source and binary forms, with or without
 * modification, are permitted only as authorizd by the OpenLADP
 * Public License.
 */
/* ACKNOWLEDGEMENTS
 * This work originally developed by Sang Seok Lim
 * 2004/06/18	03:20:00	slim@OpenLDAP.org
 */

#include "portable.h"
#include <ac/string.h>
#include <ac/socket.h>
#include <ldap_pvt.h>
#include "lutil.h"
#include <ldap.h>
#include "slap.h"

#include "component.h"
#include "asn.h"
#include <asn-gser.h>
#include <stdlib.h>

#include <string.h>

#ifndef SLAPD_COMP_MATCH
#define SLAPD_COMP_MATCH SLAPD_MOD_DYNAMIC
#endif

#ifdef SLAPD_COMP_MATCH
/*
 * Matching function : BIT STRING
 */
int
MatchingComponentBits ( char* oid, ComponentSyntaxInfo *csi_attr,
			ComponentSyntaxInfo *csi_assert )
{
	int rc;
        MatchingRule* mr;
        ComponentBits *a, *b;
                                                                          
        if ( oid ) {
                mr = retrieve_matching_rule(oid, (AsnTypeId)csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = ((ComponentBits*)csi_attr);
        b = ((ComponentBits*)csi_assert);
	rc = ( a->value.bitLen == b->value.bitLen && 
		strncmp( a->value.bits,b->value.bits,a->value.bitLen ) == 0 );
        return rc ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * Free function: BIT STRING
 */
void
FreeComponentBits ( ComponentBits* v ) {
	FreeAsnBits( &v->value );
}

/*
 * GSER Decoder : BIT STRING
 */
int
GDecComponentBits ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentBits* k, **k2;
	GAsnBits result;

        k = (ComponentBits*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBits**) v;
                *k2 = (ComponentBits*) malloc( sizeof( ComponentBits ) );
                k = *k2;
        }
        
	GDecAsnBitsContent (b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBits;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBits;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentBits;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_BITSTRING;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBits;
 
	/* Real Decoding code need to be followed */
	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : BIT STRING
 */
int
BDecComponentBitsTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentBits ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentBits ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentBits* k, **k2;
	AsnBits result;
                                                                          
        k = (ComponentBits*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBits**) v;
                *k2 = (ComponentBits*) malloc( sizeof( ComponentBits ) );
		if ( !*k2 ) return -1;
                k = *k2;
        }
        
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnBits (b, &result, bytesDecoded );
	} else {
		BDecAsnBitsContent (b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBits;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBits;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentBits;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_BITSTRING;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBits;
 
	return LDAP_SUCCESS;
}

/*
 * Component GSER BMPString Decoder
 */
int
GDecComponentBMPString (GenBuf *b, void *v, AsnLen *bytesDecoded, int mode)
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentBMPString* k, **k2;
	GBMPString result;
                                                                          
        k = (ComponentBMPString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBMPString**) v;
                *k2 = (ComponentBMPString*) malloc( sizeof( ComponentBMPString ) );
		if ( !*k2 ) return -1;
                k = *k2;
        }

        *bytesDecoded = 0;

	GDecBMPStringContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBMPString;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBMPString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentBMPString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_BMP_STR;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBMPString;
 
	return LDAP_SUCCESS;

}

/*
 * Component BER BMPString Decoder
 */
int
BDecComponentBMPStringTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentBMPString ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentBMPString ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentBMPString* k, **k2;
	BMPString result;
                                                                          
        k = (ComponentBMPString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBMPString**) v;
                *k2 = (ComponentBMPString*) malloc( sizeof( ComponentBMPString ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecBMPString ( b, &result, bytesDecoded );
	} else {
		BDecBMPStringContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBMPString;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBMPString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentBMPString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_BMP_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBMPString;
 
	return LDAP_SUCCESS;

}

/*
 * Component GSER Decoder :  UTF8 String
 */
int
GDecComponentUTF8String  (GenBuf *b, void *v,
					AsnLen *bytesDecoded, int mode) {
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentUTF8String* k, **k2;
	GUTF8String result;
                                                                          
        k = (ComponentUTF8String*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentUTF8String**) v;
                *k2 = (ComponentUTF8String*)malloc( sizeof( ComponentUTF8String ) );
                k = *k2;
        }

        *bytesDecoded = 0;

	GDecUTF8StringContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentUTF8String;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentUTF8String;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentUTF8String;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_UTF8_STR;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentUTF8String;
 
	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : UTF8String
 */
int
BDecComponentUTF8StringTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentUTF8String ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentUTF8String ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentUTF8String* k, **k2;
	UTF8String result;
                                                                          
        k = (ComponentUTF8String*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentUTF8String**) v;
                *k2 = (ComponentUTF8String*) malloc( sizeof( ComponentUTF8String ) );
                k = *k2;
        }
	
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecUTF8String ( b, &result, bytesDecoded );
	} else {
		BDecUTF8StringContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentUTF8String;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentUTF8String;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentUTF8String;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_UTF8_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentUTF8String;
}

/*
 * Component GSER Decoder :  Teletex String
 */
int
GDecComponentTeletexString  (GenBuf *b, void *v,
					AsnLen *bytesDecoded, int mode) {
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentTeletexString* k, **k2;
	GTeletexString result;
                                                                          
        k = (ComponentTeletexString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentTeletexString**) v;
                *k2 = (ComponentTeletexString*)malloc( sizeof( ComponentTeletexString ) );
                k = *k2;
        }

        *bytesDecoded = 0;

	GDecTeletexStringContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentTeletexString;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentTeletexString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentTeletexString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_VIDEOTEX_STR;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentTeletexString;
 
	return LDAP_SUCCESS;
}


/*
 * Matching function : BOOLEAN
 */
int
MatchingComponentBool(char* oid, ComponentSyntaxInfo* csi_attr,
                        ComponentSyntaxInfo* csi_assert )
{
        MatchingRule* mr;
        ComponentBool *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }

        a = ((ComponentBool*)csi_attr);
        b = ((ComponentBool*)csi_assert);

        return (a->value == b->value) ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : BOOLEAN
 */
int
GDecComponentBool ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        ComponentBool* k, **k2;
	GAsnBool result;
                                                                          
        k = (ComponentBool*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBool**) v;
                *k2 = (ComponentBool*) malloc( sizeof( ComponentBool ) );
                k = *k2;
        }

	GDecAsnBoolContent( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBool;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBool;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_BOOLEAN;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBool;
 
        return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : BOOLEAN
 */
int
BDecComponentBoolTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentBool ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentBool ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        ComponentBool* k, **k2;
	AsnBool result;
                                                                          
        k = (ComponentBool*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentBool**) v;
                *k2 = (ComponentBool*) malloc( sizeof( ComponentBool ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnBool ( b, &result, bytesDecoded );
	} else {
		BDecAsnBoolContent( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentBool;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentBool;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_BOOLEAN;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentBool;
 
        return LDAP_SUCCESS;
}

/*
 * Matching function : ENUMERATE
 */
int
MatchingComponentEnum ( char* oid, ComponentSyntaxInfo *csi_attr,
			ComponentSyntaxInfo *csi_assert )
{
        int rc;
        MatchingRule* mr;
        ComponentEnum *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = ((ComponentEnum*)csi_attr);
        b = ((ComponentEnum*)csi_assert);
        rc = (a->value == b->value);
                                                                          
        return rc ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : ENUMERATE
 */
int
GDecComponentEnum ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentEnum* k, **k2;
	GAsnEnum result;
                                                                          
        k = (ComponentEnum*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentEnum**) v;
                *k2 = (ComponentEnum*) malloc( sizeof( ComponentEnum ) );
                k = *k2;
        }

	GDecAsnEnumContent ( b, &result, bytesDecoded );
	k->value_identifier.bv_val = result.value_identifier;
	k->value_identifier.bv_len = result.len;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentEnum;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentEnum;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_ENUMERATED;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentEnum;

	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : ENUMERATE
 */
int
BDecComponentEnumTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentEnum ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentEnum ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentEnum* k, **k2;
	AsnEnum result;
                                                                          
        k = (ComponentEnum*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentEnum**) v;
                *k2 = (ComponentEnum*) malloc( sizeof( ComponentEnum ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnEnum ( b, &result, bytesDecoded );
	} else {
		BDecAsnEnumContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentEnum;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentEnum;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_ENUMERATED;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentEnum;

	return LDAP_SUCCESS;
}

/*
 * IA5String
 */
/*
 * Component BER Decoder : IA5String
 */
int
BDecComponentIA5StringTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentIA5String ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentIA5String ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentIA5String* k, **k2;
	IA5String result;
                                                                          
        k = (ComponentIA5String*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentIA5String**) v;
                *k2 = (ComponentIA5String*) malloc( sizeof( ComponentIA5String ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecIA5String ( b, &result, bytesDecoded );
	} else {
		BDecIA5StringContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentIA5String;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentIA5String;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentIA5String;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_IA5_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentIA5String;

	return LDAP_SUCCESS;
}

/*
 * Matching function : INTEGER
 */
int
MatchingComponentInt(char* oid, ComponentSyntaxInfo* csi_attr,
                        ComponentSyntaxInfo* csi_assert )
{
        MatchingRule* mr;
        ComponentInt *a, *b;
                                                                          
        if( oid ) {
                /* check if this ASN type's matching rule is overrided */
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                /* if existing function is overrided, call the overriding
function*/
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = ((ComponentInt*)csi_attr);
        b = ((ComponentInt*)csi_assert);
                                                                          
        return ( a->value == b->value ) ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : INTEGER 
 */
int
GDecComponentInt( GenBuf * b, void *v, AsnLen *bytesDecoded, int mode)
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentInt* k, **k2;
	GAsnInt result;
                                                                          
        k = (ComponentInt*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentInt**) v;
                *k2 = (ComponentInt*) malloc( sizeof( ComponentInt ) );
                k = *k2;
        }

	GDecAsnIntContent (b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentInt;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentInt;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_INTEGER;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentInt;

        return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : INTEGER 
 */
int
BDecComponentIntTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentInt ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentInt ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentInt* k, **k2;
	AsnInt result;
                                                                          
        k = (ComponentInt*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentInt**) v;
                *k2 = (ComponentInt*) malloc( sizeof( ComponentInt ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnInt (b, &result, bytesDecoded );
	} else {
		BDecAsnIntContent (b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentInt;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentInt;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_INTEGER;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentInt;
        
        return LDAP_SUCCESS;
}

/*
 * Matching function : NULL
 */
int
MatchingComponentNull ( char *oid, ComponentSyntaxInfo *csi_attr,
			ComponentSyntaxInfo *csi_assert )
{
        MatchingRule* mr;
        ComponentNull *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = ((ComponentNull*)csi_attr);
        b = ((ComponentNull*)csi_assert);
                                                                          
        return (a->value == b->value) ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : NULL
 */
int
GDecComponentNull ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentNull* k, **k2;
	GAsnNull result;
                                                                          
        k = (ComponentNull*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentNull**) v;
                *k2 = (ComponentNull*) malloc( sizeof( ComponentNull ) );
                k = *k2;
        }

	GDecAsnNullContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentNull;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentNull;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentNull;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_NULL;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentNull;

	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : NULL
 */
int
BDecComponentNullTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
	BDecComponentNull ( b, 0, 0, v,bytesDecoded,
				mode|CALL_TAG_DECODER );
}

int
BDecComponentNull ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentNull* k, **k2;
	AsnNull result;

        k = (ComponentNull*) v;
                                                                         
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentNull**) v;
                *k2 = (ComponentNull*) malloc( sizeof( ComponentNull ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnNull ( b, &result, bytesDecoded );
	}
	else {
		BDecAsnNullContent ( b, tagId, len, &result, bytesDecoded);
	}
	k->value = result;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentNull;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentNull;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentNull;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_NULL;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentNull;
	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : NumericString
 */
int
BDecComponentNumericStringTag ( GenBuf *b, void *v,
				AsnLen *bytesDecoded, int mode ) {
	BDecComponentNumericString ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentNumericString ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentNumericString* k, **k2;
	NumericString result;

        k = (ComponentNumericString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentNumericString**) v;
                *k2 = (ComponentNumericString*) malloc( sizeof( ComponentNumericString ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecNumericString ( b, &result, bytesDecoded );
	} else {
		BDecNumericStringContent ( b, tagId, len, &result, bytesDecoded);
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentNumericString;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentNumericString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentNumericString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_NUMERIC_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentNumericString;

	return LDAP_SUCCESS;
}


/*
 * Free function : OCTET STRING
 */
void
FreeComponentOcts ( ComponentOcts* v) {
	FreeAsnOcts( &v->value );
}

/*
 * Matching function : OCTET STRING
 */
int
MatchingComponentOcts ( char* oid, ComponentSyntaxInfo* csi_attr,
			ComponentSyntaxInfo* csi_assert )
{
        int rc;
        MatchingRule* mr;
        ComponentOcts *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = (ComponentOcts*) csi_attr;
        b = (ComponentOcts*) csi_assert;
	/* Assume that both of OCTET string has end of string character */
	if ( (a->value.octetLen == b->value.octetLen) &&
		strncmp ( a->value.octs, b->value.octs, a->value.octetLen ) == 0 )
        	return LDAP_COMPARE_TRUE;
	else
		return LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : OCTET STRING
 */
int
GDecComponentOcts ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char *peek_head, *data;
        int i, j, strLen;
        void* component_values;
        ComponentOcts* k, **k2;
	GAsnOcts result;
                                                                          
        k = (ComponentOcts*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentOcts**) v;
                *k2 = (ComponentOcts*) malloc( sizeof( ComponentOcts ) );
                k = *k2;
        }

	GDecAsnOctsContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentOcts;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentOcts;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentOcts;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_OCTETSTRING;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentOcts;

	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : OCTET STRING
 */
int
BDecComponentOctsTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentOcts ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentOcts ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char *peek_head, *data;
        int i, j, strLen;
        void* component_values;
        ComponentOcts* k, **k2;
	AsnOcts result;
                                                                          
        k = (ComponentOcts*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentOcts**) v;
                *k2 = (ComponentOcts*) malloc( sizeof( ComponentOcts ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnOcts ( b, &result, bytesDecoded );
	} else {
		BDecAsnOctsContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentOcts;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentOcts;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentOcts;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_OCTETSTRING;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentOcts;
	return LDAP_SUCCESS;
}

/*
 * Matching function : OBJECT IDENTIFIER
 */
int
MatchingComponentOid ( char *oid, ComponentSyntaxInfo *csi_attr ,
			ComponentSyntaxInfo *csi_assert )
{
        int rc;
        MatchingRule* mr;
        ComponentOid *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }

        a = (ComponentOid*)csi_attr;
        b = (ComponentOid*)csi_assert;
	if ( a->value.octetLen != b->value.octetLen )
		return LDAP_COMPARE_FALSE;
        rc = ( strncmp( a->value.octs, b->value.octs, a->value.octetLen ) == 0 );
                                                                          
        return rc ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : OID
 */

int
GDecComponentOid ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen, rc;
        void* component_values;
        ComponentOid* k, **k2;
	GAsnOid result;
                                                                          
        k = (ComponentOid*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentOid**) v;
                *k2 = (ComponentOid*) malloc( sizeof( ComponentOid ) );
                k = *k2;
        }
	
	if ( (rc = GDecAsnOidContent ( b, &result, bytesDecoded )) == -1 )
		return rc;
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentOid;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentOid;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentOid;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_OID;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentOid;

	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : OID
 */
int
BDecComponentOidTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentOid ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentOid ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentOid* k, **k2;
	AsnOid result;
                                                                          
        k = (ComponentOid*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentOid**) v;
                *k2 = (ComponentOid*) malloc( sizeof( ComponentOid ) );
                k = *k2;
        }
	
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnOid ( b, &result, bytesDecoded );
	} else {
		BDecAsnOidContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentOid;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentOid;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentOid;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_OID;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentOid;
	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : PrintiableString
 */

int
BDecComponentPrintableStringTag ( GenBuf *b, void *v,
					AsnLen *bytesDecoded, int mode )
{
	BDecComponentPrintableString ( b, 0, 0, v, bytesDecoded,
						mode|CALL_TAG_DECODER );
}

int
BDecComponentPrintableString( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentPrintableString* k, **k2;
	AsnOid result;
                                                                          
        k = (ComponentPrintableString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentPrintableString**) v;
                *k2 = (ComponentPrintableString*) malloc( sizeof( ComponentPrintableString ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ) {
		mode = mode & CALL_CONTENT_DECODER;
		BDecPrintableString ( b, &result, bytesDecoded );
	} else {
		BDecPrintableStringContent ( b, tagId, len, &result, bytesDecoded );
	}	
	k->value = result;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentPrintableString;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentPrintableString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentPrintableString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_PRINTABLE_STR;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentPrintableString;
	return LDAP_SUCCESS;
}

/*
 * Matching function : Real
 */
int
MatchingComponentReal (char* oid, ComponentSyntaxInfo *csi_attr,
			ComponentSyntaxInfo *csi_assert )
{
        int rc;
        MatchingRule* mr;
        ComponentReal *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }
        a = (ComponentReal*)csi_attr;
        b = (ComponentReal*)csi_assert;
        rc = (a->value == b->value);
                                                                          
        return rc ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : Real
 */
int
GDecComponentReal ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentReal* k, **k2;
	GAsnReal result;
                                                                          
        k = (ComponentReal*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentReal**) v;
                *k2 = (ComponentReal*) malloc( sizeof( ComponentReal ) );
                k = *k2;
        }

	GDecAsnRealContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentReal;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentReal;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_REAL;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentReal;

        return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : Real
 */
int
BDecComponentRealTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentReal ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentReal ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentReal* k, **k2;
	AsnReal result;
                                                                          
        k = (ComponentReal*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentReal**) v;
                *k2 = (ComponentReal*) malloc( sizeof( ComponentReal ) );
                k = *k2;
        }

	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnReal ( b, &result, bytesDecoded );
	} else {
		BDecAsnRealContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentReal;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentReal;
	k->comp_desc->cd_free = (comp_free_func*)NULL;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_REAL;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentReal;

        return LDAP_SUCCESS;
}

/*
 * Matching function : Relative OID
 */
int
MatchingComponentRelativeOid ( char* oid, ComponentSyntaxInfo *csi_attr,
					ComponentSyntaxInfo *csi_assert )
{
        int rc;
        MatchingRule* mr;
        ComponentRelativeOid *a, *b;
                                                                          
        if( oid ) {
                mr = retrieve_matching_rule(oid, csi_attr->csi_comp_desc->cd_type_id );
                if ( mr )
                        return component_value_match( mr, csi_attr , csi_assert );
        }

        a = (ComponentRelativeOid*)csi_attr;
        b = (ComponentRelativeOid*)csi_assert;

	if ( a->value.octetLen != b->value.octetLen )
		return LDAP_COMPARE_FALSE;
        rc = ( strncmp( a->value.octs, b->value.octs, a->value.octetLen ) == 0 );
                                                                          
        return rc ? LDAP_COMPARE_TRUE:LDAP_COMPARE_FALSE;
}

/*
 * GSER Decoder : RELATIVE_OID.
 */
int
GDecComponentRelativeOid ( GenBuf *b,void *v, AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentRelativeOid* k, **k2;
	GAsnRelativeOid result;
                                                                          
        k = (ComponentRelativeOid*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentRelativeOid**) v;
                *k2 = (ComponentRelativeOid*) malloc( sizeof( ComponentRelativeOid ) );
                k = *k2;
        }
	
	GDecAsnRelativeOidContent ( b, &result, bytesDecoded );
	k->value = result.value;

	k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
	k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentRelativeOid;
	k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentRelativeOid;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentRelativeOid;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
	k->comp_desc->cd_extract_i = NULL;
	k->comp_desc->cd_type = ASN_BASIC;
	k->comp_desc->cd_type_id = BASICTYPE_OID;
	k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentRelativeOid;
	
	return LDAP_SUCCESS;
}

/*
 * Component BER Decoder : RELATIVE_OID.
 */
int
BDecComponentRelativeOidTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentRelativeOid ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentRelativeOid ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentRelativeOid* k, **k2;
	AsnRelativeOid result;
                                                                          
        k = (ComponentRelativeOid*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentRelativeOid**) v;
                *k2 = (ComponentRelativeOid*) malloc( sizeof( ComponentRelativeOid ) );
                k = *k2;
        }
	
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecAsnRelativeOid ( b, &result, bytesDecoded );
	} else {
		BDecAsnRelativeOidContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentRelativeOid;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentRelativeOid;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentRelativeOid;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_RELATIVE_OID;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentRelativeOid;
	return LDAP_SUCCESS;
}

/*
 * GSER Decoder : UniverseString
 */
static int
UTF8toUniversalString( char* octs, int len){
	/* Need to be Implemented */
	return 1;
}

int
GDecComponentUniversalString ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode )
{
	GDecComponentUTF8String (b, v, bytesDecoded, mode);
	UTF8toUniversalString( ((ComponentUniversalString*)v)->value.octs,
			((ComponentUniversalString*)v)->value.octetLen );
}

/*
 * Component BER Decoder : UniverseString
 */
int
BDecComponentUniversalStringTag ( GenBuf *b, void *v, AsnLen *bytesDecoded,
				int mode ) {
	BDecComponentUniversalString ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentUniversalString ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentUniversalString* k, **k2;
	UniversalString result;
                                                                          
        k = (ComponentUniversalString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentUniversalString**) v;
                *k2 = (ComponentUniversalString*) malloc( sizeof( ComponentUniversalString ) );
                k = *k2;
        }
	
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecUniversalString ( b, &result, bytesDecoded );
	} else {
		BDecUniversalStringContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentUniversalString;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentUniversalString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentUniversalString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_UNIVERSAL_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentUniversalString;
	return LDAP_SUCCESS;
}



/*
 * Component BER Decoder : VisibleString
 */
int
BDecComponentVisibleStringTag ( GenBuf *b, void *v, AsnLen *bytesDecoded, int mode ) {
	BDecComponentVisibleString ( b, 0, 0, v, bytesDecoded, mode|CALL_TAG_DECODER );
}

int
BDecComponentVisibleString ( GenBuf *b, AsnTag tagId, AsnLen len, void *v,
			AsnLen *bytesDecoded, int mode )
{
        char* peek_head;
        int i, strLen;
        void* component_values;
        ComponentVisibleString* k, **k2;
	VisibleString result;
                                                                          
        k = (ComponentVisibleString*) v;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentVisibleString**) v;
                *k2 = (ComponentVisibleString*) malloc( sizeof( ComponentVisibleString ) );
                k = *k2;
        }
	
	if ( mode & CALL_TAG_DECODER ){
		mode = mode & CALL_CONTENT_DECODER;
		BDecVisibleString ( b, &result, bytesDecoded );
	} else {
		BDecVisibleStringContent ( b, tagId, len, &result, bytesDecoded );
	}
	k->value = result;

        k->comp_desc = malloc( sizeof( ComponentDesc ) );
	if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
		free ( *k2 );
		return -1;
	}
        k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentVisibleString;
        k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentVisibleString;
	k->comp_desc->cd_free = (comp_free_func*)FreeComponentVisibleString;
	k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
	k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
        k->comp_desc->cd_extract_i = NULL;
        k->comp_desc->cd_type = ASN_BASIC;
        k->comp_desc->cd_type_id = BASICTYPE_VISIBLE_STR;
        k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentVisibleString;
	return LDAP_SUCCESS;
}

/*
 * Routines for handling an ANY DEFINED Type
 */
void
SetAnyTypeByComponentOid ( ComponentAny *v, ComponentOid *id ) {
	Hash hash;
	void *anyInfo;

	/* use encoded oid as hash string */
	hash = MakeHash (id->value.octs, id->value.octetLen);
	if (CheckForAndReturnValue (anyOidHashTblG, hash, &anyInfo))
		v->cai = (ComponentAnyInfo*) anyInfo;
	else
		v->cai = NULL;

	if ( !v->cai ) {
	/*
	 * If not found, the data considered as octet chunk
	 * Yet-to-be-Implemented
	 */
	}
}

void
SetAnyTypeByComponentInt( ComponentAny *v, ComponentInt id) {
	Hash hash;
	void *anyInfo;

	hash = MakeHash ((char*)&id, sizeof (id));
	if (CheckForAndReturnValue (anyIntHashTblG, hash, &anyInfo))
		v->cai = (ComponentAnyInfo*) anyInfo;
	else
		v->cai = NULL;
}

int
BDecComponentAny (GenBuf *b, ComponentAny *result, AsnLen *bytesDecoded, int mode) {
        ComponentAny *k, **k2;
                                                                          
        k = (ComponentAny*) result;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentAny**) result;
                *k2 = (ComponentAny*) malloc( sizeof( ComponentAny) );
                k = *k2;
        }
	
	if ((result->cai != NULL) && (result->cai->BER_Decode != NULL)) {
		result->value = (void*) malloc ( result->cai->size );
		if ( !result->value ) return 0;
		result->cai->BER_Decode (b, result->value, (int*)bytesDecoded,
						DEC_ALLOC_MODE_1);

		k->comp_desc = malloc( sizeof( ComponentDesc ) );
		if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
			free ( *k2 );
			return -1;
		}
		k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentAny;
		k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentAny;
		k->comp_desc->cd_free = (comp_free_func*)FreeComponentAny;
		k->comp_desc->cd_pretty = (slap_syntax_transform_func*)NULL;
		k->comp_desc->cd_validate = (slap_syntax_validate_func*)NULL;
		k->comp_desc->cd_extract_i = NULL;
		k->comp_desc->cd_type = ASN_BASIC;
		k->comp_desc->cd_type_id = BASICTYPE_ANY;
		k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentAny;
		return LDAP_SUCCESS;
	}
	else {
		Asn1Error ("ERROR - Component ANY Decode routine is NULL\n");
		return 0;
	}
}

int
GDecComponentAny (GenBuf *b, ComponentAny *result, AsnLen *bytesDecoded, int mode) {
        ComponentAny *k, **k2;
                                                                          
        k = (ComponentAny*) result;
                                                                          
        if ( mode & DEC_ALLOC_MODE_0 ) {
                k2 = (ComponentAny**) result;
                *k2 = (ComponentAny*) malloc( sizeof( ComponentAny) );
                k = *k2;
        }
	if ((result->cai != NULL) && (result->cai->GSER_Decode != NULL)) {
		result->value = (void*) malloc ( result->cai->size );
		if ( !result->value ) return 0;
		result->cai->GSER_Decode (b, result->value, (int*)bytesDecoded,
						DEC_ALLOC_MODE_1);
		k->comp_desc = malloc( sizeof( ComponentDesc ) );
		if ( mode & DEC_ALLOC_MODE_0 && !k->comp_desc )  {
			free ( *k2 );
			return -1;
		}
		k->comp_desc->cd_gser_decoder = (gser_decoder_func*)GDecComponentAny;
		k->comp_desc->cd_ber_decoder = (ber_decoder_func*)BDecComponentAny;
		k->comp_desc->cd_free = (comp_free_func*)FreeComponentAny;
		k->comp_desc->cd_type = ASN_BASIC;
		k->comp_desc->cd_extract_i = NULL;
		k->comp_desc->cd_type_id = BASICTYPE_ANY;
		k->comp_desc->cd_all_match = (allcomponent_matching_func*)MatchingComponentAny;
		return LDAP_SUCCESS;
	}
	else {
		Asn1Error ("ERROR - ANY Decode routine is NULL\n");
		return 0;
	}
}

int
MatchingComponentAny (char* oid, ComponentAny *result, ComponentAny *result2) {
	void *comp1, *comp2;

	if ( result->comp_desc->cd_type_id == BASICTYPE_ANY )
		comp1 = result->value;
	else
		comp1 = result;

	if ( result2->comp_desc->cd_type_id == BASICTYPE_ANY )
		comp2 = result2->value;
	else
		comp2 = result2;
		
	if ((result->cai != NULL) && (result->cai->Match != NULL)) {
		if ( result->comp_desc->cd_type_id == BASICTYPE_ANY )
			return result->cai->Match(oid, comp1, comp2 );
		else if ( result2->comp_desc->cd_type_id == BASICTYPE_ANY )
			return result2->cai->Match(oid, comp1, comp2);
		else 
			return LDAP_INVALID_SYNTAX;
	}
	else {
		Asn1Error ("ERROR - ANY Matching routine is NULL\n");
		return LDAP_INVALID_SYNTAX;
	}
}

void*
ExtractingComponentAny ( ComponentReference* cr,  ComponentAny *result ) {
	if ((result->cai != NULL) && (result->cai->Extract != NULL)) {
		return (void*) result->cai->Extract( cr , result->value );
	}
	else {
		Asn1Error ("ERROR - ANY Extracting routine is NULL\n");
		return (void*)NULL;
	}
}

void
FreeComponentAny (ComponentAny* any) {
	if ( any->cai != NULL && any->cai->Free != NULL ) {
		any->cai->Free( any->value );
		free ( ((ComponentSyntaxInfo*)any->value)->csi_comp_desc );
		free ( any->value );
	}
	else
		Asn1Error ("ERROR - ANY Free routine is NULL\n");
}

void
InstallAnyByComponentInt (int anyId, ComponentInt intId, unsigned int size,
			EncodeFcn encode, gser_decoder_func* G_decode,
			ber_tag_decoder_func* B_decode, ExtractFcn extract,
			MatchFcn match, FreeFcn free,
			PrintFcn print)
{
	ComponentAnyInfo *a;
	Hash h;

	a = (ComponentAnyInfo*) malloc (sizeof (ComponentAnyInfo));
	a->anyId = anyId;
	a->oid.octs = NULL;
	a->oid.octetLen = 0;
	a->intId = intId;
	a->size = size;
	a->Encode = encode;
	a->GSER_Decode = G_decode;
	a->BER_Decode = B_decode;
	a->Match = match;
	a->Extract = extract;
	a->Free = free;
	a->Print = print;

	if (anyIntHashTblG == NULL)
		anyIntHashTblG = InitHash();

	h = MakeHash ((char*)&intId, sizeof (intId));

	if(anyIntHashTblG != NULL)
		Insert(anyIntHashTblG, a, h);
}

void
InstallAnyByComponentOid (int anyId, AsnOid *oid, unsigned int size,
			EncodeFcn encode, gser_decoder_func* G_decode,
			ber_tag_decoder_func* B_decode, ExtractFcn extract,
			 MatchFcn match, FreeFcn free, PrintFcn print)
{
	ComponentAnyInfo *a;
	Hash h;

	a = (ComponentAnyInfo*) malloc (sizeof (ComponentAnyInfo));
	a->anyId = anyId;
	a->oid.octs = NULL;
	a->oid.octetLen = 0;
	a->size = size;
	a->Encode = encode;
	a->GSER_Decode = G_decode;
	a->BER_Decode = B_decode;
	a->Match = match;
	a->Extract = extract;
	a->Free = free;
	a->Print = print;

	h = MakeHash (oid->octs, oid->octetLen);

	if (anyOidHashTblG == NULL)
		anyOidHashTblG = InitHash();

	if(anyOidHashTblG != NULL)
		Insert(anyOidHashTblG, a, h);
}

int
BDecComponentTop  (
ber_decoder_func *decoder _AND_
GenBuf *b _AND_
AsnTag tag _AND_
AsnLen elmtLen _AND_
void **v _AND_
AsnLen *bytesDecoded _AND_
int mode) {
	tag = BDecTag ( b, bytesDecoded );
	elmtLen = BDecLen ( b, bytesDecoded );
	if ( tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE) ) {
		printf("Invliad Tag\n");
		exit (1);
	}
		
	return (*decoder)( b, tag, elmtLen, (ComponentSyntaxInfo*)v,(int*)bytesDecoded, mode );
}

#endif

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

#include <string.h>

#ifndef SLAPD_COMP_MATCH
#define SLAPD_COMP_MATCH SLAPD_MOD_DYNAMIC
#endif


OD_entry* gOD_table = NULL;
AsnTypetoMatchingRuleTable* gATMR_table = NULL;

int
load_derived_matching_rule ( char* cfg_path ){
}

MatchingRule*
retrieve_matching_rule( char* mr_oid, AsnTypeId type ) {
	char* tmp;
	struct berval mr_name = BER_BVNULL;
	AsnTypetoMatchingRuleTable* atmr;

	for ( atmr = gATMR_table ; atmr ; atmr = atmr->atmr_table_next ) {
		if ( strcmp( atmr->atmr_oid, mr_oid ) == 0 ) {
			tmp = atmr->atmr_table[type].atmr_mr_name;
			if ( tmp ) {
				mr_name.bv_val = tmp;
				mr_name.bv_len = strlen( tmp );
				return mr_bvfind ( &mr_name );
			}
		}
	}
	return (MatchingRule*)NULL;
}

OD_entry*
retrieve_oid_decoder_table ( char* oid ) {
	OD_entry* curr_entry;
	for ( curr_entry = gOD_table ; curr_entry != NULL ;
				curr_entry = curr_entry->oe_next ) {
		if ( strcmp ( curr_entry->oe_oid , oid ) == 0 )
			return curr_entry;
	}
	return (OD_entry*) NULL;
}

int
add_OD_entry ( char* oid, gser_decoder_func* gser_decoder ,
		ber_decoder_func ber_decoder, converter_func* converter ) {
	OD_entry* new_entry;

	if ( !gOD_table ) {
		gOD_table = new_entry = (OD_entry*) malloc( sizeof ( OD_entry ) );
		gOD_table->oe_next = NULL;
		gOD_table->oe_prev = NULL;
	}
	else {
		new_entry = (OD_entry*) malloc( sizeof ( OD_entry ) );
		if ( !new_entry ) return -1;
		gOD_table->oe_prev = new_entry;
		new_entry->oe_next = gOD_table;
		new_entry->oe_prev = NULL;
		gOD_table = new_entry;
	}

	strcpy ( new_entry->oe_oid ,oid );
	new_entry->oe_gser_decoder = gser_decoder;
	new_entry->oe_ber_decoder = ber_decoder;
	new_entry->oe_converter = converter;

	return 1;
}

int
remove_OD_entry ( char* oid ) {
	OD_entry* curr_entry;
	for ( curr_entry = gOD_table ; curr_entry != NULL ;
				curr_entry = curr_entry->oe_next ) {
		if ( strcmp ( curr_entry->oe_oid , oid ) == 0 ) {
			if ( !curr_entry->oe_next ) {
				if ( curr_entry->oe_prev ) {
					curr_entry->oe_prev->oe_next = NULL;
				}
			} else {
				curr_entry->oe_prev->oe_next = curr_entry->oe_next;
				curr_entry->oe_next->oe_prev = curr_entry->oe_prev;
			}
			free ( curr_entry );
			return 1;
		}
	}
	return -1;
}

void* 
comp_convert_attr_to_comp LDAP_P (( Attribute* a, Syntax *syn, struct berval* bv ))
{

	char* peek_head;
        int mode, bytesDecoded, size, rc;
        void* component;
	char* oid = a->a_desc->ad_type->sat_atype.at_oid ;
        GenBuf* b;
        ExpBuf* buf;
	OD_entry* od_entry;
	
	/* look for the decoder registered for the given attribute */
	od_entry =  retrieve_oid_decoder_table ( oid );
	if ( !od_entry || !od_entry->oe_ber_decoder ) return (void*)NULL;
	if ( od_entry->oe_converter ) {
		size = (*od_entry->oe_converter)( bv );
		if ( size <= 0 ) return (void*)NULL;
	}

        ExpBufInit( 2048 );
        buf = ExpBufAllocBufAndData();
        ExpBufResetInWriteRvsMode( buf );
        ExpBuftoGenBuf( buf, &b );
        BufPutSegRvs( b, bv->bv_val, bv->bv_len );
        BufResetInReadMode( b );
	
	mode = DEC_ALLOC_MODE_2;
	/*
	 * How can we decide which decoder will be called, GSER or BER?
	 * Currently BER decoder is called for a certificate.
	 * The flag of Attribute will say something about it in the future
	 */
	if ( slap_syntax_is_ber ( syn ) ) {
		rc =BDecComponentTop(od_entry->oe_ber_decoder, b, 0,0,
				&component,&bytesDecoded,mode ) ;
	}
	else {
		rc = od_entry->oe_gser_decoder(b, component,&bytesDecoded,mode);
	}
	if ( rc == -1 )
		return (void*)NULL;
	else
		return component;
}

void
comp_free_component LDAP_P (( ComponentSyntaxInfo *csi )) {
	if ( csi->csi_comp_desc->cd_free )
		csi->csi_comp_desc->cd_free(csi);
	free ( csi->csi_comp_desc );
	free ( csi );
	return;
}

int
comp_convert_assert_to_comp LDAP_P (( ComponentSyntaxInfo *csi_attr, struct berval* bv,
			ComponentSyntaxInfo** csi, int* len, int mode ))
{
	GenBuf* genBuf;
	ExpBuf* buf;
	gser_decoder_func *decoder = csi_attr->csi_comp_desc->cd_gser_decoder;

	ExpBufInit( 2048 );
	buf = ExpBufAllocBufAndData();
	ExpBufResetInWriteRvsMode( buf );
	ExpBuftoGenBuf( buf, &genBuf );
	BufPutSegRvs( genBuf, bv->bv_val, bv->bv_len );
	BufResetInReadMode( genBuf );

	if ( csi_attr->csi_comp_desc->cd_type_id == BASICTYPE_ANY )
		decoder = ((ComponentAny*)csi_attr)->cai->GSER_Decode;

	return (*decoder)( genBuf, csi, len, mode );
}

int intToAscii( int value, char* buf ) {
	int minus=0,i,temp;
	char digit;
	int total_num_digits;

	if ( value == 0 ){
		buf[0] = '0';
		return 1;
	}

	if ( value < 0 ){
		minus = 1;
		value = value*(-1);
		buf[0] = '-';
	}
	
	/* How many digits */
	for ( temp = value, total_num_digits=0 ; temp ; total_num_digits++ )
		temp = temp/10;

	total_num_digits += minus;

	for ( i = minus ; value ; i++ ) {
		buf[ total_num_digits - i  ]= (char)(value%10 + '0');
		value = value/10;
	}
	return i;
}

int
comp_convert_asn_to_ldap LDAP_P(( ComponentSyntaxInfo* csi, struct berval* bv ))
{
	int value;
	Syntax* syn;
	AsnTypetoSyntax* asn_to_syn =
		&asn_to_syntax_mapping_tbl[csi->csi_comp_desc->cd_type_id];
	if ( asn_to_syn->ats_syn_oid )
		csi->csi_syntax = syn_find ( asn_to_syn->ats_syn_oid );
	else 
		csi->csi_syntax = NULL;

        switch ( csi->csi_comp_desc->cd_type_id ) {
          case BASICTYPE_BOOLEAN :
		if ( ((ComponentBool*)csi)->value > 0 ) {
			strcpy ( bv->bv_val , "TRUE" );
			bv->bv_len = 4;
		}
		else {
			strcpy ( bv->bv_val , "FALSE" );
			bv->bv_len = 5;
		}
                break ;
          case BASICTYPE_NULL :
                bv->bv_val = (char *) &((ComponentNull*)csi)->value;
                bv->bv_len = sizeof(char);
                break;
          case BASICTYPE_INTEGER :
		bv->bv_len = intToAscii(((ComponentInt*)csi)->value, bv->bv_val );
		if ( bv->bv_len <= 0 ) return LDAP_INVALID_SYNTAX;
                break;
          case BASICTYPE_REAL :
                bv->bv_val = (char *) &((ComponentReal*)csi)->value;
                bv->bv_len = sizeof(double);
                break;
          case BASICTYPE_ENUMERATED :
                bv->bv_val = (char *) &((ComponentEnum*)csi)->value;
                bv->bv_len = sizeof(int);
                break;
          case BASICTYPE_OID :
          case BASICTYPE_OCTETSTRING :
          case BASICTYPE_BITSTRING :
          case BASICTYPE_NUMERIC_STR :
          case BASICTYPE_PRINTABLE_STR :
          case BASICTYPE_UNIVERSAL_STR :
          case BASICTYPE_IA5_STR :
          case BASICTYPE_BMP_STR :
          case BASICTYPE_UTF8_STR :
          case BASICTYPE_UTCTIME :
          case BASICTYPE_GENERALIZEDTIME :
          case BASICTYPE_GRAPHIC_STR :
          case BASICTYPE_VISIBLE_STR :
          case BASICTYPE_GENERAL_STR :
          case BASICTYPE_OBJECTDESCRIPTOR :
          case BASICTYPE_VIDEOTEX_STR :
          case BASICTYPE_T61_STR :
          case BASICTYPE_OCTETCONTAINING :
          case BASICTYPE_BITCONTAINING :
          case BASICTYPE_RELATIVE_OID :
                bv->bv_val = ((ComponentOcts*)csi)->value.octs;
                bv->bv_len = ((ComponentOcts*)csi)->value.octetLen;
                break;
	  case BASICTYPE_ANY :
		csi = ((ComponentAny*)csi)->value;
		if ( csi->csi_comp_desc->cd_type != ASN_BASIC ||
			csi->csi_comp_desc->cd_type_id == BASICTYPE_ANY )
			return LDAP_INVALID_SYNTAX;
		return comp_convert_asn_to_ldap( csi, bv );
          case COMPOSITE_ASN1_TYPE :
          case RDNSequence :
          case RelativeDistinguishedName :
          case TelephoneNumber :
          case FacsimileTelephoneNumber__telephoneNumber :
		break;
          case DirectoryString :
                bv->bv_val = ((ComponentOcts*)csi)->value.octs;
                bv->bv_len = ((ComponentOcts*)csi)->value.octetLen;
                break;
          case ASN_COMP_CERTIFICATE :
          case ASNTYPE_END :
		break;
          default :
                /*Only ASN Basic Type can be converted into LDAP string*/
		return LDAP_INVALID_SYNTAX;
        }

	if ( csi->csi_syntax && csi->csi_syntax->ssyn_validate ) {
		if ( csi->csi_syntax->ssyn_validate(csi->csi_syntax, bv) != LDAP_SUCCESS )
			return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

#if SLAPD_COMP_MATCH == SLAPD_MOD_DYNAMIC

#include "certificate.h"

extern convert_attr_to_comp_func* attr_converter;
extern convert_assert_to_comp_func* assert_converter;
extern convert_asn_to_ldap_func* csi_converter;
extern free_component_func* component_destructor;

int init_module(int argc, char *argv[]) {
	/*
	 * Initialize function pointers in slapd
	 */
	attr_converter = comp_convert_attr_to_comp;
	assert_converter = comp_convert_assert_to_comp;
	csi_converter = comp_convert_asn_to_ldap;
	component_destructor = comp_free_component;
	/* file path needs to be */
	load_derived_matching_rule ("derived_mr.cfg");
	/* the initialization for example X.509 certificate */
	init_module_AuthenticationFramework();
	return 0;
}

#endif /* SLAPD_PASSWD */

/* Copyright 2004 IBM Corporation
 * All rights reserved.
 * Redisribution and use in source and binary forms, with or without
 * modification, are permitted only as  authorizd by the OpenLADP
 * Public License.
 */
/* ACKNOWLEDGEMENTS
 * This work originally developed by Sang Seok Lim
 * 2004/06/18	03:20:00	slim@OpenLDAP.org
 */

#ifndef _H_COMPONENT_MODULE
#define _H_COMPONENT_MODULE

#include "portable.h"
#include <ac/string.h>
#include <ac/socket.h>
#include <ldap_pvt.h>
#include "lutil.h"
#include <ldap.h>
#include <slap.h>

#include <asn-incl.h>
#include "asn.h"
#include <asn-gser.h>
#include <string.h>

#define MAX_IDENTIFIER_LEN	128
#define COMPONENTNOT_NULL(ptr)  ((ptr) != NULL)

/*
 * BIT STRING
 */
typedef struct ComponentBits {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnBits value;
} ComponentBits;

#define GASNBITS_PRESENT(abits) ((abits)->value.bits != NULL)
#define COMPONENTBITS_PRESENT(abits) ((abits)->value.bits != NULL)
int GDecComponentBits (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentBits (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentBits (char* oid, ComponentSyntaxInfo *bits1 , ComponentSyntaxInfo* bits2);
#define ExtractingComponentBits( mem_op, cr,data ) NULL

/*
 * BMP String
 */
typedef struct ComponentBMPString {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	BMPString value;
} ComponentBMPString;

int GDecComponentBMPString (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentBMPString (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentBMPString MatchingComponentOcts
#define ExtractingComponentBMPString( mem_op, cr, data ) NULL
#define FreeComponentBMPString FreeComponentOcts

/*
 * BOOLEAN
 */
typedef struct ComponentBool {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnBool value;
} ComponentBool;

int GDecComponentBool ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentBool ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentBool (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentBool( mem_op, cr, data ) NULL
#define FreeComponentBool(v) NULL

/*
 * ENUMERTED
 */
typedef struct ComponentEnum {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnEnum value;
	struct berval value_identifier;/*Why this value is defined here?*/
} ComponentEnum;

int GDecComponentEnum ( void* mem_op, GenBuf *a, void *result, AsnLen *bytesDecoded,int mode);
int BDecComponentEnum ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentEnum (char *oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo * b);
#define ExtractingComponentEnum( mem_op, cr, data ) NULL
#define FreeComponentEnum FreeComponentInt

/*
 * IA5 String
 */
typedef struct ComponentIA5String {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	IA5String value;
} ComponentIA5String;

#define GDecComponentIA5String GDecComponentUTF8String
int BDecComponentIA5String ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentIA5String MatchingComponentOcts
#define ExtractingComponentIA5String(mem_op, cr,data)	NULL
#define FreeComponentIA5String FreeComponentOcts


/*
 * INTEGER
 */
typedef struct ComponentInt {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	int value;
} ComponentInt;

#define GNOT_NULL(ptr) ((ptr) != NULL)

int GDecComponentInt ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode );
int BDecComponentInt ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentInt (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentInt(mem_op, cr,data)	NULL
#define FreeComponentInt(v) NULL

/*
 * LIST Data Structure for C_LIST
 */
typedef struct ComponentList {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnList comp_list;
} ComponentList;

/*
 * NULL
 */
typedef struct ComponentNull {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnNull value;
} ComponentNull;

int GDecComponentNull ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentNull ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentNullTag ( void* mem_op, GenBuf *b, void *v, AsnLen *bytesDecoded, int mode );
int MatchingComponentNull (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentNull(mem_op, cr, data)	NULL
#define FreeComponentNull NULL

/*
 * Numeric String
 */
typedef struct ComponentNumericString {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	NumericString value;
} ComponentNumericString;

#define GDecComponentNumericString GDecComponentUTF8String
int BDecComponentNumericString ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentNumericString MatchingComponentOcts
#define ExtractingComponentNumericString(mem_op, cr,data)	NULL
#define FreeComponentNumericString FreeComponentOcts

/*
 * OCTETS STRING
 */
typedef struct ComponentOcts {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnOcts value;
} ComponentOcts;

#define GASNOCTS_PRESENT(aocts) ((aocts)->value.octs != NULL)

int GDecComponentOcts (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentOcts (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentOcts (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentOcts(mem_op,cr,data)	NULL
void FreeComponentOcts( ComponentOcts* octs );

/*
 * OID (Object Identifier)
 */
typedef struct ComponentOid {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnOid value;
} ComponentOid;

#define GASNOID_PRESENT(aoid) ASNOCTS_PRESENT(aoid)

int GDecComponentOid (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentOid (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentOid (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentOid(mem_op, cr, data)	NULL
#define FreeComponentOid FreeComponentOcts

/*
 * Printable String
 */
typedef struct ComponentPrintableString{
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	PrintableString value;
} ComponentPrintableString;

#define GDecComponentPrintableString GDecComponentUTF8String
int BDecComponentPrintableString (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentPrintableStringTag (void* mem_op, GenBuf *b, void *v, AsnLen *bytesDecoded, int mode );
#define MatchingComponentPrintableString MatchingComponentOcts
#define ExtractingComponentPrintableString(mem_op, cr, data)	NULL
#define FreeComponentPrintableString FreeComponentOcts

/*
 * REAL
 */
typedef struct ComponentReal{
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnReal value;
} ComponentReal;

int GDecComponentReal (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentReal (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentReal (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentReal( mem_op, cr, data )	NULL
#define FreeComponentReal(v) NULL

/*
 * Relative OID
 */

typedef struct ComponentRelativeOid {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	AsnRelativeOid value;
} ComponentRelativeOid;

int GDecComponentRelativeOid ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentRelativeOid ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentRelativeOid (char* oid, ComponentSyntaxInfo *a, ComponentSyntaxInfo *b);
#define ExtractingComponentRelativeOid( mem_op, cr, data ) NULL
#define FreeComponentRelativeOid FreeComponentOid

/*
 * Teletex String
 */
typedef struct ComponentTeletexString {
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	TeletexString value;
} ComponentTeletexString;

int GDecComponentTeletexString ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode );
#define BDecComponentTeletexString BDecComponentOcts
#define MatchingComponentTeletexString MatchingComponentOcts
#define ExtractingComponentTeletexString(mem_op,cr,data)
#define FreeComponentTeletexString FreeComponentOcts


/*
 * Universal String
 */
typedef struct ComponentUniversalString{
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	UniversalString value;
} ComponentUniversalString;

int GDecComponentUniversalString ( void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentUniversalString ( void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentUniversalString MatchingComponentOcts
#define ExtractingComponentUniversalString(mem_op,cr,data)
#define FreeComponentUniversalString FreeComponentOcts

/*
 * UTF8 String
 */
typedef struct ComponentUTF8String{
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	UTF8String value;
} ComponentUTF8String;

int GDecComponentUTF8String (void* mem_op, GenBuf *b, void *result, AsnLen *bytesDecoded, int mode);
int BDecComponentUTF8String (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentUTF8String MatchingComponentOcts
#define ExtractingComponentUTF8String(mem_op,cr,data)
#define FreeComponentUTF8String FreeComponentOcts

/*
 * Visible String
 */
typedef struct ComponentVisibleString{
	void* syntax;
	ComponentDesc* comp_desc;
	struct berval identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	VisibleString value;
} ComponentVisibleString;

#define GDecComponentVisibleString GDecComponentUTF8String
int BDecComponentVisibleString (void* mem_op, GenBuf *b, AsnTag tagId, AsnLen len, void *result, AsnLen *bytesDecoded, int mode);
#define MatchingComponentVisibleString MatchingComponentOcts
#define ExtractingComponentVisibleString(mem_op,cr,data)
#define FreeComponentVisibleString FreeComponentOcts

/*
 * ANY and ANY DEFINED BY
 */

typedef int (*MatchFcn) (char*, void*, void*);
typedef void* (*ExtractFcn) (void*, ComponentReference*, void * );

typedef struct ComponentAnyInfo
{
	int		anyId;
	AsnOid		oid;
	ComponentInt	intId;
	unsigned int	size;
	EncodeFcn	Encode;
	gser_decoder_func* GSER_Decode;
	ber_tag_decoder_func* BER_Decode;
	ExtractFcn	Extract;
	MatchFcn	Match;
	FreeFcn		Free;
	PrintFcn	Print;
} ComponentAnyInfo;

typedef struct ComponentAny{
	void*		syntax;
	ComponentDesc	*comp_desc;
	struct berval	identifier;
	char id_buf[MAX_IDENTIFIER_LEN];
	ComponentAnyInfo	*cai;
	void		*value;
} ComponentAny;

typedef ComponentAny ComponentAnyDefinedBy;

#define BDecComponentAnyDefinedBy BDecComponentAny
#define GDecComponentAnyDefinedBy GDecComponentAny
#define MatchingComponentAnyDefinedBy MatchingComponentAny
#define FreeComponentAnyDefinedBy FreeComponentAny

int BDecComponentAny ( void* mem_op, GenBuf *b, ComponentAny *result, AsnLen *bytesDecoded, int mode);
int GDecComponentAny ( void* mem_op, GenBuf *b, ComponentAny *result, AsnLen *bytesDecoded, int mode);
int MatchingComponentAny (char* oid, ComponentAny *a, ComponentAny *b);
void FreeComponentAny ( ComponentAny*);

void InstallAnyByComponentInt (int anyId, ComponentInt intId, unsigned int size, EncodeFcn encode, gser_decoder_func* G_decode, ber_tag_decoder_func B_decode, ExtractFcn extract, MatchFcn match, FreeFcn free, PrintFcn print);

void InstallAnyByComponentOid (int anyId, AsnOid *oid, unsigned int size, EncodeFcn encode, gser_decoder_func* G_decode, ber_tag_decoder_func* B_decode, ExtractFcn extract, MatchFcn match, FreeFcn free, PrintFcn print);


/*
 * UTCTime
 */
typedef ComponentVisibleString ComponentUTCTime;
#define GDecComponentUTCTime GDecComponentVisibleString
#define BDecComponentUTCTime BDecComponentOcts
#define MatchingComponentUTCTime MatchingComponentOcts
#define ExtractingComponentUTCTime(mem_op,cr,data) NULL
#define FreeComponentUTCTime FreeComponentOcts

/*
 * GeneralizedTime
 */
typedef ComponentVisibleString ComponentGeneralizedTime;
#define GDecComponentGeneralizedTime GDecComponentVisibleString
#define BDecComponentGeneralizedTime BDecComponentOcts
#define MatchingComponentGeneralizedTime MatchingComponentOcts
#define ExtractingComponentGeneralizedTime(mem_op,cr,data) NULL
#define FreeComponentGeneralizedTime FreeComponentOcts

typedef int converter_func LDAP_P ((
	struct berval* in ));

typedef struct asntype_to_syntax {
	AsnTypeId	ats_typeId;
	/* Syntax Descriptor */
	char		*ats_syn_name;
	/* Syntax OID */
	char		*ats_syn_oid;
	Syntax		*ats_syn;
} AsnTypetoSyntax;

typedef struct asntype_to_matchingrule {
	AsnTypeId	atmr_typeId;
	char*		atmr_mr_name;
	/*Implicitly corresponding LDAP syntax OID*/
	char*		atmr_syn_oid;
	MatchingRule	*atmr_mr;
} AsnTypetoMatchingRule;

typedef struct asntype_to_matchingrule_table {
	char*	atmr_oid;
	struct asntype_to_matchingrule atmr_table[ASNTYPE_END];
	struct asntype_to_matchingrule_table* atmr_table_next;
} AsnTypetoMatchingRuleTable;

extern AsnTypetoSyntax asn_to_syntax_mapping_tbl[];

#define MAX_OID_LEN 256
#define MAX_OD_ENTRY 8

/*
 * Object Identifier and corresponding Syntax Decoder Table
 */
typedef struct OID_Decoder_entry {
        char            oe_oid[MAX_OID_LEN];
        gser_decoder_func*   oe_gser_decoder;
        ber_decoder_func*   oe_ber_decoder;
	converter_func* oe_converter;
        struct OID_Decoder_entry*       oe_next;
        struct OID_Decoder_entry*       oe_prev;
} OD_entry;

void
m_convert_asn_to_ldap ( ComponentSyntaxInfo* csi, struct berval* bv);
int
m_convert_assert_to_comp ( gser_decoder_func* decoder, struct berval* bv,
                        ComponentSyntaxInfo** csi, int len, int mode );
void*
m_convert_attr_to_comp ( Attribute* a, struct berval* bv );

/*
 * Decoder Modes
 * Different operation is required to handle Decoding(2), Extracted Component
 * decoding(0), ANY DEFINED TYPe(2)
 * b0 : Component Alloc(yes)
 *	Constructed type : Component Alloc (Yes)
 *	Primitive type : Component Alloc (Yes)
 * 	set to mode 2 in inner decoders
 * b1 : Component Alloc (No)
 *	Constructed type : Component Alloc (No)
 *	Primitive type : Component Alloc (No)
 *	set to mode 2 in inner decoders
 * b2 : Default Mode
 *	Constructed type : Component Alloc (Yes)
 *	Primitive type : Component Alloc (No)
 * in addition to above modes, the 4th bit has special meaning,
 * b4 : if the 4th bit is clear, DecxxxContent is called
 * b4 : if the 4th bit is set, Decxxx is called, then it is cleared.
 */
#define DEC_ALLOC_MODE_0	0x01
#define DEC_ALLOC_MODE_1	0x02
#define DEC_ALLOC_MODE_2	0x04
#define CALL_TAG_DECODER	0x08
#define CALL_CONTENT_DECODER	~0x08

#define OID_ALL_COMP_MATCH "1.2.36.79672281.1.13.6"
#define OID_COMP_FILTER_MATCH "1.2.36.79672281.1.13.2"
#define MAX_LDAP_STR_LEN 128

MatchingRule*
retrieve_matching_rule( char* mr_oid, AsnTypeId type );

#endif

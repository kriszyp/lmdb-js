/* asn.h -- Component Filter Match Routines */
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

#ifdef LDAP_COMP_MATCH
#ifndef _H_ASN
#define _H_ASN

#define NUM_ENCODING_TYPE 2

typedef enum { ASN_BASIC, ASN_COMPOSITE } AsnType;

typedef enum AsnTypeId {
	BASICTYPE_BOOLEAN,	/* 1 */
	BASICTYPE_INTEGER, 
	BASICTYPE_BITSTRING,
	BASICTYPE_OCTETSTRING,
	BASICTYPE_NULL,
	BASICTYPE_OID,
	BASICTYPE_REAL,
	BASICTYPE_ENUMERATED,
	BASICTYPE_NUMERIC_STR,
	BASICTYPE_PRINTABLE_STR,
	BASICTYPE_UNIVERSAL_STR,
	BASICTYPE_IA5_STR,
	BASICTYPE_BMP_STR,
	BASICTYPE_UTF8_STR,
	BASICTYPE_UTCTIME,
	BASICTYPE_GENERALIZEDTIME,
	BASICTYPE_GRAPHIC_STR,
	BASICTYPE_VISIBLE_STR,
	BASICTYPE_GENERAL_STR,
	BASICTYPE_OBJECTDESCRIPTOR,
	BASICTYPE_VIDEOTEX_STR,
	BASICTYPE_T61_STR,
	BASICTYPE_OCTETCONTAINING,
	BASICTYPE_BITCONTAINING,
	BASICTYPE_RELATIVE_OID,	/* 25 */
	/* Embedded Composite Types*/
	COMPOSITE_ASN1_TYPE,
	/* A New ASN.1 types including type reference */
	RDNSequence,
	RelativeDistinguishedName,
	TelephoneNumber,
	FacsimileTelephoneNumber_telephoneNumber,
	DirectoryString,
	/* Newly Defined ASN.1 Type, Manually registered */
	ASN_T1,
	/* ASN.1 Type End */
	ASNTYPE_END
} AsnTypeId;
#endif
#endif

/* $OpenLDAP$ */
/*
 * Copyright 1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/*
 * ldap-schema.h - Header for basic schema handling functions that can be
 *		used by both clients and servers.
 */

#ifndef _LDAP_SCHEMA_H
#define _LDAP_SCHEMA_H 1

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/* Codes for parsing errors */

#define LDAP_SCHERR_OUTOFMEM		1
#define LDAP_SCHERR_UNEXPTOKEN		2
#define LDAP_SCHERR_NOLEFTPAREN		3
#define LDAP_SCHERR_NORIGHTPAREN	4
#define LDAP_SCHERR_NODIGIT		5
#define LDAP_SCHERR_BADNAME		6
#define LDAP_SCHERR_BADDESC		7
#define LDAP_SCHERR_BADSUP		8
#define LDAP_SCHERR_DUPOPT		9
#define LDAP_SCHERR_EMPTY		10

typedef struct ldap_syntax {
	char *syn_oid;		/* REQUIRED */
	char *syn_desc;		/* OPTIONAL */
} LDAP_SYNTAX;

typedef struct ldap_matchingrule {
	char *mr_oid;		/* REQUIRED */
	char **mr_names;	/* OPTIONAL */
	char *mr_desc;		/* OPTIONAL */
	int  mr_obsolete;	/* OPTIONAL */
	char *mr_syntax_oid;	/* REQUIRED */
} LDAP_MATCHING_RULE;

typedef struct ldap_attributetype {
	char *at_oid;		/* REQUIRED */
	char **at_names;	/* OPTIONAL */
	char *at_desc;		/* OPTIONAL */
	int  at_obsolete;	/* 0=no, 1=yes */
	char *at_sup_oid;	/* OPTIONAL */
	char *at_equality_oid;	/* OPTIONAL */
	char *at_ordering_oid;	/* OPTIONAL */
	char *at_substr_oid;	/* OPTIONAL */
	char *at_syntax_oid;	/* OPTIONAL */
	int  at_syntax_len;	/* OPTIONAL */
	int  at_single_value;	/* 0=no, 1=yes */
	int  at_collective;	/* 0=no, 1=yes */
	int  at_no_user_mod;	/* 0=no, 1=yes */
	int  at_usage;		/* 0=userApplications, 1=directoryOperation,
				   2=distributedOperation, 3=dSAOperation */
} LDAP_ATTRIBUTE_TYPE;

typedef struct ldap_objectclass {
	char *oc_oid;		/* REQUIRED */
	char **oc_names;	/* OPTIONAL */
	char *oc_desc;		/* OPTIONAL */
	int  oc_obsolete;	/* 0=no, 1=yes */
	char **oc_sup_oids;	/* OPTIONAL */
	int  oc_kind;		/* 0=ABSTRACT, 1=STRUCTURAL, 2=AUXILIARY */
	char **oc_at_oids_must;	/* OPTIONAL */
	char **oc_at_oids_may;	/* OPTIONAL */
} LDAP_OBJECT_CLASS;

#define LDAP_SCHEMA_NO				0
#define LDAP_SCHEMA_YES				1

#define LDAP_SCHEMA_USER_APPLICATIONS		0
#define LDAP_SCHEMA_DIRECTORY_OPERATION		1
#define LDAP_SCHEMA_DISTRIBUTED_OPERATION	2
#define LDAP_SCHEMA_DSA_OPERATION		3

#define LDAP_SCHEMA_ABSTRACT			0
#define LDAP_SCHEMA_STRUCTURAL			1
#define LDAP_SCHEMA_AUXILIARY			2

LDAP_F( LDAP_CONST char * )
ldap_syntax2name LDAP_P((
	LDAP_SYNTAX * syn ));

LDAP_F( LDAP_CONST char * )
ldap_matchingrule2name LDAP_P((
	LDAP_MATCHING_RULE * mr ));

LDAP_F( LDAP_CONST char * )
ldap_attributetype2name LDAP_P((
	LDAP_ATTRIBUTE_TYPE * at ));

LDAP_F( LDAP_CONST char * )
ldap_objectclass2name LDAP_P((
	LDAP_OBJECT_CLASS * oc ));

LDAP_F( void )
ldap_syntax_free LDAP_P((
	LDAP_SYNTAX * syn ));

LDAP_F( void )
ldap_matchingrule_free LDAP_P((
	LDAP_MATCHING_RULE * mr ));

LDAP_F( void )
ldap_attributetype_free LDAP_P((
	LDAP_ATTRIBUTE_TYPE * at ));

LDAP_F( void )
ldap_objectclass_free LDAP_P((
	LDAP_OBJECT_CLASS * oc ));

LDAP_F( LDAP_OBJECT_CLASS * )
ldap_str2objectclass LDAP_P((
	LDAP_CONST char * s,
	int * code,
	LDAP_CONST char ** errp ));

LDAP_F( LDAP_ATTRIBUTE_TYPE * )
ldap_str2attributetype LDAP_P((
	LDAP_CONST char * s,
	int * code,
	LDAP_CONST char ** errp ));

LDAP_F( LDAP_SYNTAX * )
ldap_str2syntax LDAP_P((
	LDAP_CONST char * s,
	int * code,
	LDAP_CONST char ** errp ));

LDAP_F( LDAP_MATCHING_RULE * )
ldap_str2matchingrule LDAP_P((
	LDAP_CONST char * s,
	int * code,
	LDAP_CONST char ** errp ));

LDAP_F( char *)
ldap_objectclass2str LDAP_P((
	LDAP_CONST LDAP_OBJECT_CLASS * oc ));

LDAP_F( char *)
ldap_attributetype2str LDAP_P((
	LDAP_CONST LDAP_ATTRIBUTE_TYPE * at ));

LDAP_F( char *)
ldap_syntax2str LDAP_P((
	LDAP_CONST LDAP_SYNTAX * syn ));

LDAP_F( char *)
ldap_matchingrule2str LDAP_P((
	LDAP_CONST LDAP_MATCHING_RULE * mr ));

LDAP_F( char *)
ldap_scherr2str LDAP_P((
	int code ));

LDAP_END_DECL

#endif


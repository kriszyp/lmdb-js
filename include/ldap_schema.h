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

LDAP_F(LDAP_OBJECT_CLASS *) ldap_str2objectclass LDAP_P(( char * s, int * code, char ** errp ));
LDAP_F(LDAP_ATTRIBUTE_TYPE *) ldap_str2attributetype LDAP_P(( char * s, int * code, char ** errp ));
LDAP_F( char *) ldap_objectclass2str LDAP_P(( LDAP_OBJECT_CLASS * oc ));
LDAP_F( char *) ldap_attributetype2str LDAP_P(( LDAP_ATTRIBUTE_TYPE * at ));

LDAP_END_DECL

#endif


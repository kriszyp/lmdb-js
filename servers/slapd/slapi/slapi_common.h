/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#ifndef SLAPI_COMMON_H
#define SLAPI_COMMON_H

LDAP_BEGIN_DECL


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define dn_normalize_case	dn_normalize
#define SLAPD_NO_MEMORY    	7
#define ANYBODY_STRING 		"CN=ANYBODY"

extern int slap_debug;

int
dn_check(char *, int *);

typedef struct strlist {
	char *string;
	struct strlist *next;
} StrList;

LDAP_END_DECL

#endif /* SLAPI_COMMON_H */


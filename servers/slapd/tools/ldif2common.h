/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ldif2common.h - common definitions for the ldif2* tools */

#ifndef LDIF2COMMON_H_
#define LDIF2COMMON_H_

#include "ldap_defaults.h"
#include "../slap.h"

enum ldiftool {
	LDIF2LDBM = 1, LDIF2INDEX, LDIF2ID2ENTRY, LDIF2ID2CHILDREN
};


extern	char	*progname;
extern	char	*tailorfile;
extern	char	*inputfile;
extern	char	*sbindir;
extern	int     cmdkids;
extern	int 	dbnum;


void slap_ldif_init LDAP_P(( int, char **, int, const char *, int ));
int  slap_read_ldif LDAP_P(( int *, char **, int *, ID *, int ));


#endif /* LDIF2COMMON_H_ */

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

#ifndef _SLAPI_CL_H
#define _SLAPI_CL_H

#define TIME_SIZE 20
#define OBJECTCLASS "objectclass"
#define TOP "top"
#define CHANGE_TIME "changetime"
#define CHANGE_TYPE "changetype"
#define CHANGE_TARGETDN "targetdn"
#define CHANGES	"changes"
#define CHANGE_NUMBER "changenumber"
/*
 * FIXME: I get complaints like "ADD" being redefined - first definition
 * being in "/usr/include/arpa/nameser.h:552"
 */
#undef ADD
#define ADD "add: "
#define ADDLEN 5
#define DEL "delete: "
#define DELLEN 8
#define REPLACE "replace: "
#define REPLEN 9
#define MOD "modify"
#define MODRDN "modrdn"
#define CHANGE_LOGENTRY "changelogentry"
#define IBM_CHANGE_LOGENTRY "ibm-changelog"
#define CL_NEWRDN "newrdn"
#define CL_DELRDN "deleteoldrdn"
#define CHANGE_INITIATOR "ibm-changeInitiatorsName" 

void slapi_register_changelog_suffix(char *suffix);
char **slapi_get_changelog_suffixes();
void slapi_update_changelog_counters(long curNum, long numEntries);
char *slapi_get_cl_firstNum();
char *slapi_get_cl_lastNum();
int slapi_add_to_changelog(Slapi_Entry *ent, char *suffix, char *chNum, Operation* op);	
int slapi_delete_changelog(char *dn, char *suffix, char *chNum, Operation* op);	
int slapi_modify_changelog(char *dn,LDAPMod	*mods,char *suffix, char *chNum, Operation* op); 
int slapi_modifyrdn_changelog(char *olddn, char *newRdn, int delRdn, char *suffix, char *chNum, Operation* op);
Backend * slapi_cl_get_be(char *dn);

#endif /* _SLAPI_CL_H */


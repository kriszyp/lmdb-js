/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#ifndef SLAPI_OPS_H
#define SLAPI_OPS_H

Slapi_PBlock *slapi_search_internal( char *base, int scope, char *filter, 
	LDAPControl **controls, char **attrs, int attrsonly );
Slapi_PBlock *slapi_search_internal_bind( char *bindDN, char *base, int scope, char *filter, 
	LDAPControl **controls, char **attrs, int attrsonly ); /* d58508 */
Slapi_PBlock *slapi_modify_internal( char *dn, LDAPMod **mods,
        LDAPControl **controls, int log_change );
Slapi_PBlock *slapi_add_entry_internal( Slapi_Entry * e, LDAPControl **controls, int log_change );
Slapi_PBlock *slapi_add_internal( char * dn, LDAPMod **attrs, LDAPControl **controls, int log_changes );
Slapi_PBlock *slapi_add_entry_internal( Slapi_Entry * e, LDAPControl **controls, int log_change );
Slapi_PBlock *slapi_delete_internal( char * dn,  LDAPControl **controls, int log_change );
Slapi_PBlock *slapi_modrdn_internal( char * olddn, char * newrdn, int deloldrdn, LDAPControl **controls, int log_change);
/*
Slapi_PBlock *slapi_modrdn_internal( char * olddn, char * newrdn, char *newParent, int deloldrdn, LDAPControl **controls, int log_change);
*/
char **slapi_get_supported_extended_ops(void);
int duplicateBVMod( LDAPMod *pMod, LDAPMod **ppNewMod );

#endif /* SLAPI_OPS_H */


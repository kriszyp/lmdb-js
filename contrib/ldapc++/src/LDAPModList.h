/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_MOD_LIST_H
#define LDAP_MOD_LIST_H

#include <ldap.h>
#include <list>
#include "LDAPModification.h"

typedef list<LDAPModification> ModList;

class LDAPModList{

	public : 
		LDAPModList();
		LDAPModList(const LDAPModList&);

		void addModification(const LDAPModification &mod);
		LDAPMod** toLDAPModArray();

	private : 
		ModList m_modList;
};
#endif //LDAP_MOD_LIST_H



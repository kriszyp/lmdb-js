/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPModList.h,v 1.3 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_MOD_LIST_H
#define LDAP_MOD_LIST_H

#include <ldap.h>
#include <list>
#include "LDAPModification.h"

typedef list<LDAPModification> ModList;

class LDAPModList{
	private : 
		ModList m_modList;

	public : 
		LDAPModList();
		LDAPModList(const LDAPModList&);

		void addModification(const LDAPModification &mod);
		LDAPMod** toLDAPModArray();

};
#endif //LDAP_MOD_LIST_H



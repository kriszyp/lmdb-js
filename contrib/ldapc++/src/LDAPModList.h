/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_MOD_LIST_H
#define LDAP_MOD_LIST_H

#include <ldap.h>
#include <list>
#include <LDAPModification.h>

typedef std::list<LDAPModification> ModList;

/**
 * This container class is used to store multiple LDAPModification-objects.
 */
class LDAPModList{

	public : 
        /**
         * Constructs an empty list.
         */   
		LDAPModList();
		
        /**
         * Copy-constructor
         */
        LDAPModList(const LDAPModList&);

        /**
         * Adds one element to the end of the list.
         * @param mod The LDAPModification to add to the std::list.
         */
		void addModification(const LDAPModification &mod);

        /**
         * Translates the list to a 0-terminated array of
         * LDAPMod-structures as needed by the C-API
         */
        LDAPMod** toLDAPModArray();

	private : 
		ModList m_modList;
};
#endif //LDAP_MOD_LIST_H



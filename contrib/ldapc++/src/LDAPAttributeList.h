/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAttributeList.h,v 1.5 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_ATTRIBUTE_LIST_H
#define LDAP_ATTRIBUTE_LIST_H

#include <list>
#include <ldap.h>
#include "LDAPAttribute.h"
#include "LDAPAsynConnection.h"
#include "LDAPMessage.h"

typedef list<LDAPAttribute> AttrList;

class LDAPAttributeList{
	private :
		AttrList m_attrs;

	public :
		LDAPAttributeList(const LDAPAsynConnection *ld, LDAPMessage *msg);
		LDAPAttributeList(const LDAPAttributeList& al);
		LDAPAttributeList();
		~LDAPAttributeList();
		void addAttribute(const LDAPAttribute& attr);
		void find(char* name);
		LDAPMod** toLDAPModArray();
		
		friend ostream& operator << (ostream& s, const LDAPAttributeList& al);
};
#endif // LDAP_ATTRIBUTE_LIST_H


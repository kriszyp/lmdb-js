/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPEntry.h,v 1.4 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_ENTRY_H
#define LDAP_ENTRY_H
#include <ldap.h>

#include "LDAPAsynConnection.h"
#include "LDAPAttributeList.h"

class LDAPEntry{
	private :
		LDAPAttributeList *m_attrs;
		char *m_dn;

	public :
		LDAPEntry(const LDAPEntry& entry);
		LDAPEntry(const char *dn, LDAPAttributeList *attrs);
		LDAPEntry(const LDAPAsynConnection *ld, LDAPMessage *msg);
		~LDAPEntry();
		void setDN(const char* dn);
		void setAttributes(LDAPAttributeList *attrs);
		char* getDN();
		LDAPAttributeList* getAttributes();
		friend ostream& operator << (ostream& s, const LDAPEntry& le);
};
#endif  //LDAP_ENTRY_H

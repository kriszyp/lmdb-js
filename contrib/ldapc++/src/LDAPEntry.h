/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_ENTRY_H
#define LDAP_ENTRY_H
#include <ldap.h>

#include "LDAPAsynConnection.h"
#include "LDAPAttributeList.h"

class LDAPEntry{

	public :
		LDAPEntry(const LDAPEntry& entry);
		LDAPEntry(const string& dn=string(), 
                const LDAPAttributeList *attrs=new LDAPAttributeList());
		LDAPEntry(const LDAPAsynConnection *ld, LDAPMessage *msg);
		~LDAPEntry();
		void setDN(const string& dn);
		void setAttributes(LDAPAttributeList *attrs);
		const string getDN() const ;
		const LDAPAttributeList* getAttributes() const;
		friend ostream& operator << (ostream& s, const LDAPEntry& le);
	
    private :
		LDAPAttributeList *m_attrs;
		string m_dn;
};
#endif  //LDAP_ENTRY_H

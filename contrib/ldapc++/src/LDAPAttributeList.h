/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_ATTRIBUTE_LIST_H
#define LDAP_ATTRIBUTE_LIST_H

#include <list>
class LDAPAttribute;
class LDAPAsynConnection;
class LDAPMsg;

typedef list<LDAPAttribute> AttrList;

class LDAPAttributeList{
    typedef AttrList::const_iterator const_iterator;

	private :
		AttrList m_attrs;

	public :
		LDAPAttributeList(const LDAPAttributeList& al);
        
        /*!
         * @throws LDAPException if msg does not contain an entry
         */
		LDAPAttributeList(const LDAPAsynConnection *ld, LDAPMessage *msg);
		LDAPAttributeList();
        virtual ~LDAPAttributeList();

        size_t size() const;
        const_iterator begin() const;
        const_iterator end() const;
		void addAttribute(const LDAPAttribute& attr);
		LDAPMod** toLDAPModArray() const;
		
		friend ostream& operator << (ostream& s, const LDAPAttributeList& al);
};
#endif // LDAP_ATTRIBUTE_LIST_H


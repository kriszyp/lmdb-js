/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_REFERENCE_LIST_H
#define LDAP_REFERENCE_LIST_H

#include <list>

class LDAPSearchReference;

typedef list<LDAPSearchReference> RefList;

class LDAPReferenceList{
    typedef RefList::const_iterator const_iterator;

    public:
        LDAPReferenceList();
        LDAPReferenceList(const LDAPReferenceList& rl);
        ~LDAPReferenceList();

        size_t size() const;
        const_iterator begin() const;
        const_iterator end() const;
        void addReference(const LDAPSearchReference& e);

    private:
        RefList m_refs;
};
#endif // LDAP_REFERENCE_LIST_H


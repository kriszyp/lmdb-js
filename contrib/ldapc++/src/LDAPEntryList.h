/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_ENTRY_LIST_H
#define LDAP_ENTRY_LIST_H

#include <list>

class LDAPEntry;
   
typedef list<LDAPEntry> EntryList;
class LDAPEntryList{
    typedef EntryList::const_iterator const_iterator;

    private:
        EntryList m_entries;

    public:
        LDAPEntryList(const LDAPEntryList& el);
        LDAPEntryList();
        ~LDAPEntryList();

        size_t size() const;
        const_iterator begin() const;
        const_iterator end() const;
        void addEntry(const LDAPEntry& e);
};
#endif // LDAP_ENTRY_LIST_H

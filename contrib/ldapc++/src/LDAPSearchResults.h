/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_SEARCH_RESULTS_H
#define LDAP_SEARCH_RESULTS_H

#include "LDAPEntry.h"
#include "LDAPEntryList.h"
#include "LDAPMessage.h"
#include "LDAPMessageQueue.h"
#include "LDAPReferenceList.h"
#include "LDAPSearchReference.h"

class LDAPResult;

class LDAPSearchResults{
    private :
        LDAPEntryList entryList;
        LDAPReferenceList refList;
        LDAPEntryList::const_iterator entryPos;
        LDAPReferenceList::const_iterator refPos;
    public:
        LDAPSearchResults();
        LDAPResult* readMessageQueue(LDAPMessageQueue* msg);
        LDAPEntry* getNext();
};
#endif //LDAP_SEARCH_RESULTS_H



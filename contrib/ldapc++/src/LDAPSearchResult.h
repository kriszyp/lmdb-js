/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_SEARCH_RESULT_H
#define LDAP_SEARCH_RESULT_H

#include "LDAPMessage.h"
#include "LDAPEntry.h"

class LDAPRequest;

class LDAPSearchResult : public LDAPMsg{
	public:
		LDAPSearchResult(const LDAPRequest *req, LDAPMessage *msg);
        LDAPSearchResult(const LDAPSearchResult& res);
		virtual ~LDAPSearchResult();
		const LDAPEntry* getEntry() const;
	
    private:
		LDAPEntry *entry;
};
#endif //LDAP_SEARCH_RESULT_H

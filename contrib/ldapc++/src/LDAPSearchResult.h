/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPSearchResult.h,v 1.4 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_SEARCH_RESULT_H
#define LDAP_SEARCH_RESULT_H

#include "LDAPMessage.h"
#include "LDAPEntry.h"

class LDAPRequest;

class LDAPSearchResult : public LDAPMsg{
	private:
		LDAPEntry *entry;
	public:
		LDAPSearchResult(LDAPRequest *req, LDAPMessage *msg);
		virtual ~LDAPSearchResult();
		LDAPEntry* getEntry();
};
#endif //LDAP_SEARCH_RESULT_H

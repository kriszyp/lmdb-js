/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPSearchResult.cpp,v 1.6 2000/08/31 17:43:49 rhafer Exp $

#include <iostream>

#include "debug.h"
#include"LDAPSearchResult.h"
#include "LDAPRequest.h"

LDAPSearchResult::LDAPSearchResult(LDAPRequest *req, LDAPMessage *msg) 
        : LDAPMsg(msg){
	DEBUG(LDAP_DEBUG_TRACE,"LDAPSearchResult::LDAPSearchResult()" << endl);
    entry = new LDAPEntry(req->getConnection(), msg);
}

LDAPSearchResult::~LDAPSearchResult(){
	DEBUG(LDAP_DEBUG_TRACE,"LDAPSearchResult::~LDAPSearchResult()" << endl);
	delete entry;
}

LDAPEntry* LDAPSearchResult::getEntry(){
	DEBUG(LDAP_DEBUG_TRACE,"LDAPSearchResult::getEntry()" << endl);
	return entry;
}


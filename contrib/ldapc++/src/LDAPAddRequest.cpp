/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include <ldap.h>

#include "debug.h"

#include "LDAPAddRequest.h"
#include "LDAPEntry.h"
#include "LDAPException.h"
#include "LDAPMessageQueue.h"

LDAPAddRequest::LDAPAddRequest(const LDAPAddRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAddRequest::LDAPAddRequest(LDAPAddRequest&)"
            << endl);
}

LDAPAddRequest::LDAPAddRequest(const LDAPEntry *entry, 
        const LDAPAsynConnection *connect, const LDAPConstraints *cons,
        bool isReferral=false) 
        : LDAPRequest(connect, cons, isReferral){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAddRequest::LDAPAddRequest()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   entry:" << *entry << endl
            << "   isReferral:" << isReferral << endl);
    m_requestType = LDAPRequest::ADD;
    m_entry = new LDAPEntry(*entry);
}

LDAPAddRequest::~LDAPAddRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAddRequest::~LDAPAddRequest()" << endl);
    delete m_entry;
}

LDAPMessageQueue* LDAPAddRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAddRequest::sendRequest()" << endl);
    int msgID=0;
    LDAPAttributeList *attrList = m_entry->getAttributes();
    int err=ldap_add_ext(m_connection->getSessionHandle(),
            m_entry->getDN(),attrList->toLDAPModArray(), 
            m_cons->getSrvCtrlsArray(), m_cons->getClCtrlsArray(),&msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPAddRequest::followReferral(LDAPUrlList *urls){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAddRequest::followReferral()"<< endl);
    cerr << "to be implemented" << endl;
    return 0;
}


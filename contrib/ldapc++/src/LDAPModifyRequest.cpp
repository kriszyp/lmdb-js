/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include <debug.h>

#include "LDAPModifyRequest.h"
#include "LDAPException.h"
#include "LDAPMessageQueue.h"

LDAPModifyRequest::LDAPModifyRequest(const LDAPModifyRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_TRACE, 
            "LDAPModifyRequest::LDAPModifyRequest(LDAPModifyRequest&)" 
            << endl);
}

LDAPModifyRequest::LDAPModifyRequest(const char *dn, 
        const LDAPModList *modList, const LDAPAsynConnection *connect,
        const LDAPConstraints *cons, bool isReferral=false) :
        LDAPRequest(connect, cons, isReferral){
    DEBUG(LDAP_DEBUG_TRACE, 
            "LDAPModifyRequest::LDAPModifyRequest(LDAPModifyRequest&)" 
            << endl);            
    DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl);

    m_dn = strdup(dn);
    m_modList = new LDAPModList(*modList);
}

LDAPModifyRequest::~LDAPModifyRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModifyRequest::~LDAPModifyRequest()" << endl);
    delete m_dn;
    delete m_modList;
}

LDAPMessageQueue* LDAPModifyRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModifyRequest::sendRequest()" << endl);
    int msgID=0;
    int err=ldap_modify_ext(m_connection->getSessionHandle(),m_dn,
            m_modList->toLDAPModArray(), m_cons->getSrvCtrlsArray(), 
            m_cons->getClCtrlsArray(),&msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPModifyRequest::followReferral(LDAPUrlList *refs){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModifyRequest::followReferral()" << endl);
    cerr << "to be implemented ..." << endl;
    return 0;
}


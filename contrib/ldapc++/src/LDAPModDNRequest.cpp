/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include "debug.h"

#include "LDAPModDNRequest.h"
#include "LDAPException.h"
#include "LDAPUrlList.h"

LDAPModDNRequest::LDAPModDNRequest(const LDAPModDNRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_TRACE, 
            "LDAPModDNRequest::LDAPModDNRequest(LDAPModDNRequest&)" << endl);
}

LDAPModDNRequest::LDAPModDNRequest(const char *dn, const char *newRDN, 
        bool deleteOld, const char *newParentDN, 
        const LDAPAsynConnection *connect, 
        const LDAPConstraints *cons, bool isReferral=false):
        LDAPRequest(connect, cons, isReferral){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModDNRequest::LDAPModDNRequest()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl
            << "   newRDN:" << newRDN << endl
            << "   deleteOld:" << deleteOld << endl
            << "   newParentDN:" << newParentDN << endl);
    assert(dn);
    m_dn = strdup(dn);
    assert(newRDN);
    m_newRDN = strdup(newRDN);
    if (newParentDN){
        m_newParentDN = strdup(newParentDN);
    }else{
        m_newParentDN = 0;
    }
    m_deleteOld=deleteOld;
}

LDAPModDNRequest::~LDAPModDNRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModDNRequest::~LDAPModDNRequest()" << endl);
    delete[] m_dn;
    delete[] m_newRDN;
    delete[] m_newParentDN;
}

LDAPMessageQueue* LDAPModDNRequest::sendRequest(){
    int msg_id;
    int err=ldap_rename(m_connection->getSessionHandle(),m_dn,m_newRDN,
            m_newParentDN,m_deleteOld ? 1 : 0, m_cons->getSrvCtrlsArray(),
            m_cons->getClCtrlsArray(),&msg_id);
    if(err!=LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msg_id;
        return new LDAPMessageQueue(this);
    }

}

LDAPRequest* LDAPModDNRequest::followReferral(LDAPUrlList *urls){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPModifyRequest::followReferral()" << endl);
    cerr << "to be implemented ..." << endl;
    return 0;
}


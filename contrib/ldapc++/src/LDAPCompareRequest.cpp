/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include "debug.h"

#include "LDAPCompareRequest.h"
#include "LDAPException.h"
#include "LDAPMessageQueue.h"

LDAPCompareRequest::LDAPCompareRequest(const LDAPCompareRequest& req){
    DEBUG(LDAP_DEBUG_TRACE, 
            "LDAPCompareRequest::LDAPCompareRequest(LDAPCompareRequest&)" 
            << endl);
}

LDAPCompareRequest::LDAPCompareRequest(const char *dn, 
        const LDAPAttribute *attr, const LDAPAsynConnection *connect, 
        const LDAPConstraints *cons, bool isReferral=false) :
        LDAPRequest(connect, cons, isReferral){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPCompareRequest::LDAPCompareRequest()" 
            << endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl 
            << "   attr:" << attr << endl);
    m_requestType=LDAPRequest::COMPARE;
    if(dn != 0){
        m_dn=strdup(dn);
    }
    if(attr != 0){
        //TODO: test for number of values ???
        m_attr = new LDAPAttribute(*attr);
    }
} 
    
LDAPCompareRequest::~LDAPCompareRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPCompareRequest::~LDAPCompareRequest()" 
            << endl);
    delete[] m_dn;
    delete m_attr;
}

LDAPMessageQueue* LDAPCompareRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPCompareRequest::sendRequest()" << endl);
    int msgID=0;
    BerValue **tmp=m_attr->getValues();
    int err=ldap_compare_ext(m_connection->getSessionHandle(),m_dn,
            m_attr->getName(), tmp[0], m_cons->getSrvCtrlsArray(), 
            m_cons->getClCtrlsArray(), &msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPCompareRequest::followReferral(LDAPUrlList *urls){
	DEBUG(LDAP_DEBUG_TRACE, "LDAPCompareRequest::followReferral()" << endl);
    cerr << "to be implemented" << endl;
    return 0;
}


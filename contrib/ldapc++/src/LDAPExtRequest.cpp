/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>
#include <lber.h>

#include "debug.h"

#include "LDAPExtRequest.h"
#include "LDAPException.h"

LDAPExtRequest::LDAPExtRequest(const LDAPExtRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_TRACE,
            "LDAPExtRequest::LDAPExtRequest(LDAPExtRequest&)" << endl);
}

LDAPExtRequest::LDAPExtRequest(const char *oid, const BerValue* data, 
        const LDAPAsynConnection *connect, const LDAPConstraints *cons,
        bool isReferral=false) : LDAPRequest(connect, cons, isReferral){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPExtRequest::LDAPExtRequest()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   oid:" << oid << endl);
    assert(oid);
    m_oid=strdup(oid);
    if(data){
        m_data=ber_bvdup(data);
    }else{
        m_data=0;
    }
}

LDAPExtRequest::~LDAPExtRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPExtRequest::~LDAPExtRequest()" << endl);
    delete[] m_oid;
    ber_bvfree(m_data);
}

LDAPMessageQueue* LDAPExtRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPExtRequest::sendRequest()" << endl);
    int msgID=0;
    int err=ldap_extended_operation(m_connection->getSessionHandle(),m_oid, 
            m_data, m_cons->getSrvCtrlsArray(), m_cons->getClCtrlsArray(),
            &msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPExtRequest::followReferral(LDAPUrlList *urls){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPExtRequest::followReferral()" << endl);
    cerr << "to be implemented" << endl;
    return 0;
}


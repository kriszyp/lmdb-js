/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include "debug.h"

#include "LDAPBindRequest.h"
#include "LDAPException.h"

LDAPBindRequest::LDAPBindRequest(const LDAPBindRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_TRACE, 
            "LDAPBindRequest::LDAPBindRequest(LDAPBindRequest&)" << endl);
}

LDAPBindRequest::LDAPBindRequest(const char *dn, const char *passwd, 
        const LDAPAsynConnection *connect, const LDAPConstraints *cons,
        bool isReferral=false) : LDAPRequest(connect, cons, isReferral){
   DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::LDAPBindRequest()" << endl);
   DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl
           << "   passwd:" << passwd << endl);
    m_dn = strdup(dn);
    m_cred = ber_bvstr(passwd);
    m_mech = LDAP_SASL_SIMPLE;
}

LDAPBindRequest::~LDAPBindRequest(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::~LDAPBindRequest()" << endl);
    delete[] m_dn;
    ber_bvfree(m_cred);
    delete[] m_mech;
}

LDAPMessageQueue* LDAPBindRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::sendRequest()" << endl);
    int msgID=0;
    int err=ldap_sasl_bind(m_connection->getSessionHandle(),m_dn, 
            m_mech, m_cred, m_cons->getSrvCtrlsArray(),
            m_cons->getClCtrlsArray(),&msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPBindRequest::followReferral(LDAPUrlList *urls){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::followReferral()" << endl);
    return 0;
}


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include "debug.h"

#include "LDAPDeleteRequest.h"
#include "LDAPException.h"
#include "LDAPMessageQueue.h"

LDAPDeleteRequest::LDAPDeleteRequest( const LDAPDeleteRequest& req) :
        LDAPRequest(req){
	DEBUG(LDAP_DEBUG_TRACE, 
		"LDAPDeleteRequest::LDAPDeleteRequest(LDAPDeleteRequest&)" 
		<< endl);
}

LDAPDeleteRequest::LDAPDeleteRequest(const char *dn, 
        const LDAPAsynConnection *connect, const LDAPConstraints *cons,
        bool isReferral=false) : LDAPRequest(connect, cons, isReferral) {

	DEBUG(LDAP_DEBUG_TRACE, "LDAPDeleteRequest::LDAPDeleteRequest()" << endl);
	DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl);
    m_requestType=LDAPRequest::DELETE;
    if(dn != 0){
        m_dn=strdup(dn);
    }
}

LDAPDeleteRequest::~LDAPDeleteRequest(){
	DEBUG(LDAP_DEBUG_TRACE, "LDAPDeleteRequest::~LDAPDeleteRequest()" << endl);
    delete[] m_dn;
}

LDAPMessageQueue* LDAPDeleteRequest::sendRequest(){
	DEBUG(LDAP_DEBUG_TRACE, "LDAPDeleteRequest::sendRequest()" << endl);
    int msgID=0;
    int err=ldap_delete_ext(m_connection->getSessionHandle(),m_dn, 
            m_cons->getSrvCtrlsArray(), m_cons->getClCtrlsArray(),&msgID);
    if(err != LDAP_SUCCESS){
        delete this;
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPDeleteRequest::followReferral(LDAPUrlList *refs){
	DEBUG(LDAP_DEBUG_TRACE, "LDAPDeleteRequest::followReferral()" << endl);
    cerr << "to be implemented" << endl;
    return 0;
}


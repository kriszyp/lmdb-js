/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPRequest.cpp,v 1.11 2000/08/31 17:43:49 rhafer Exp $

#include "debug.h"
#include "LDAPRequest.h"
#include "LDAPReferral.h"

LDAPRequest::LDAPRequest(){
}

LDAPRequest::LDAPRequest(const LDAPRequest& req){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPRequest::LDAPRequest(LDAPRequest&)" << endl);
}

LDAPRequest::LDAPRequest(const LDAPAsynConnection* con, 
       const LDAPConstraints* cons, bool isReferral){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::LDAPRequest()" << endl);
    m_connection=con;
    if(cons == 0){
        cons=con->getConstraints();
    }
    m_cons=new LDAPConstraints( *cons);
    m_isReferral=isReferral;    
}

LDAPRequest::~LDAPRequest(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::~LDAPRequest()" << endl);
    delete m_cons;
}

const LDAPConstraints* LDAPRequest::getConstraints(){
    return m_cons;
}

const LDAPAsynConnection* LDAPRequest::getConnection(){
    return m_connection;
}

int LDAPRequest::getType() const {
    return m_requestType;
}

int LDAPRequest::getMsgID() const {
    return m_msgID;
}

bool LDAPRequest::isReferral() const {
    return m_isReferral;
}

/*
   bool LDAPRequest::doRebind() const {
    cerr << "doRebind not implemented always returns true" << endl;
    return true;
}
*/


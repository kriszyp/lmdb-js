/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "debug.h"
#include "LDAPRequest.h"

using namespace std;

LDAPRequest::LDAPRequest(){
    DEBUG(LDAP_DEBUG_CONSTRUCT, "LDAPRequest::LDAPRequest()" << endl);
}

LDAPRequest::LDAPRequest(const LDAPRequest& req){
    DEBUG(LDAP_DEBUG_CONSTRUCT, "LDAPRequest::LDAPRequest(&)" << endl);
    m_isReferral=req.m_isReferral;
    m_cons = new LDAPConstraints(*(req.m_cons));
    m_connection = req.m_connection;
    m_parent = req.m_parent;
    m_hopCount = req.m_hopCount;
    m_msgID = req.m_msgID;
}

LDAPRequest::LDAPRequest(LDAPAsynConnection* con, 
       const LDAPConstraints* cons,bool isReferral, const LDAPRequest* parent){
    DEBUG(LDAP_DEBUG_CONSTRUCT,"LDAPRequest::LDAPRequest()" << endl);
    m_connection=con;
    if(cons == 0){
        m_cons=new LDAPConstraints( *(con->getConstraints()) );
    }else{
        m_cons=new LDAPConstraints( *cons);
    }
    m_isReferral=isReferral; 
    if(m_isReferral){
        m_hopCount = (parent->getHopCount()+1);
        m_parent= parent;
    }else{
        m_hopCount=0;
        m_parent=0;
    }
}

LDAPRequest::~LDAPRequest(){
    DEBUG(LDAP_DEBUG_DESTROY,"LDAPRequest::~LDAPRequest()" << endl);
    delete m_cons;
}

const LDAPConstraints* LDAPRequest::getConstraints() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getConstraints()" << endl);
    return m_cons;
}

const LDAPAsynConnection* LDAPRequest::getConnection() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getConnection()" << endl);
    return m_connection;
}

int LDAPRequest::getType() const {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getType()" << endl);
    return m_requestType;
}

int LDAPRequest::getMsgID() const {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getMsgId()" << endl);
    return m_msgID;
}

int LDAPRequest::getHopCount() const {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getHopCount()" << endl);
    return m_hopCount;
}

const LDAPRequest* LDAPRequest::getParent() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::getParent()" << endl);
    return m_parent;
}

bool LDAPRequest::isReferral() const {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::isReferral()" << endl);
    return m_isReferral;
}

bool LDAPRequest::equals(const LDAPRequest* req) const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::equals()" << endl);
    if( (this->m_requestType == req->getType()) && 
        (this->m_connection->getHost() == req->m_connection->getHost()) && 
        (this->m_connection->getPort() == req->m_connection->getPort())
      ){
        return true;
    }return false;        
}

bool LDAPRequest::isCycle() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::isCycle()" << endl);
    const LDAPRequest* parent=m_parent;
    if(parent != 0){
        do{
            if(this->equals(parent)){
                return true;
            }else{
                parent=parent->getParent();
            }
        }
        while(parent != 0);
    }
    return false;
}

void LDAPRequest::unbind() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPRequest::unbind()" << endl);
    m_connection->unbind();
}

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "debug.h"
#include "LDAPSearchRequest.h"
#include "LDAPException.h"
#include "LDAPSearchReference.h"
#include "LDAPRequest.h"
#include "LDAPReferral.h"
#include "LDAPUrl.h"

LDAPSearchRequest::LDAPSearchRequest(const LDAPSearchRequest& req ) :
        LDAPRequest (req){
    DEBUG(LDAP_DEBUG_TRACE, 
        "LDAPSearchRequest::LDAPSearchRequest(LDAPSearchRequest&" << endl);
}
        

LDAPSearchRequest::LDAPSearchRequest(const char *base, int scope, 
        const char *filter, char **attrs, const LDAPAsynConnection *connect,
        const LDAPConstraints* cons, bool isReferral) 
            : LDAPRequest (connect,cons,isReferral) {
    
    DEBUG(LDAP_DEBUG_TRACE,"LDAPSearchRequest:LDAPSearchRequest" << endl);
    m_requestType=LDAPRequest::SEARCH;
    //insert some validating and copying here  
    m_base=strdup(base);
    m_scope=scope;
  
    if (filter != 0 ){
        m_filter=strdup(filter);
    }else{
        m_filter=0;
    }

    if (attrs != 0){
        size_t size=0;
        for (char** i=attrs; *i != 0; i++){
            size++;
        }
        m_attrs = new char*[size+1];
        m_attrs[size]=0;
        int j=0;
        for (char** i=attrs; *i != 0; i++,j++){
            m_attrs[j]=strdup(*i);
        }
    }else{
        m_attrs = 0;
    }
}

LDAPSearchRequest::~LDAPSearchRequest(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPSearchRequest::~LDAPSearchRequest" << endl);
    delete[] m_base;
    delete[] m_filter;
    if (m_attrs != 0){
        for (char** i=m_attrs; *i != 0; i++){
            delete[] *i;
        }
    }
    delete[] m_attrs;
}

LDAPMessageQueue* LDAPSearchRequest::sendRequest(){
    int msgID; 
    DEBUG(LDAP_DEBUG_TRACE, "LDAPSearchRequest::sendRequest()" << endl);
    int err=ldap_search_ext(m_connection->getSessionHandle(), m_base, m_scope,
            m_filter, m_attrs, 0, m_cons->getSrvCtrlsArray(), 
            m_cons->getClCtrlsArray(), m_cons->getTimeoutStruct(),
            m_cons->getSizeLimit(), &msgID );
    if (err != LDAP_SUCCESS){  
        delete this;
        throw LDAPException(err);
    } else {
        m_msgID=msgID;
        return  new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPSearchRequest::followReferral(LDAPUrlList *ref){
    LDAPUrl *usedUrl;
    DEBUG(LDAP_DEBUG_TRACE, "LDAPSearchRequest::followReferral()" << endl);
    LDAPAsynConnection *con = getConnection()->referralConnect(ref, &usedUrl);
    if (con != 0){
        const char *base= usedUrl->getDN();
        // TODO maybe the scope and filter have to be adjusted
        int scope = m_scope;
        char *filter=0;
        if (m_filter != 0){
           filter = strdup(m_filter);
        }
        return new LDAPSearchRequest(base, scope, filter, 0, con, m_cons,true);
    }else{
        return 0;
    }
}



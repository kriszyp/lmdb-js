/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPSearchReference.cpp,v 1.7 2000/08/31 17:43:49 rhafer Exp $

#include <iostream>

#include "debug.h"
#include "LDAPSearchReference.h"
#include "LDAPException.h"
#include "LDAPRequest.h"
#include "LDAPUrl.h"

LDAPSearchReference::LDAPSearchReference(LDAPRequest *req, LDAPMessage *msg) : 
        LDAPMsg(msg){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPSearchReference::LDAPSearchReference()"
            << endl;)    
    char **ref=0;
    const LDAPAsynConnection* con=req->getConnection();
    int err = ldap_parse_reference(con->getSessionHandle(), msg, &ref, 0,0);
    if (err != LDAP_SUCCESS){
        throw LDAPException(err);
    }else{
        char **tmp;
        for (tmp=ref; *tmp != 0; tmp++){   
            m_urlList.push_back( new LDAPUrl(*tmp) );
            DEBUG(LDAP_DEBUG_PARAMETER,"   URL:" << *tmp << endl);
        }
    }
}

LDAPSearchReference::~LDAPSearchReference(){
    LDAPUrlList::const_iterator i;
    for(i=m_urlList.begin(); i!=m_urlList.end(); i++){
        delete *i;
    }
}

LDAPUrlList* LDAPSearchReference::getURLs(){
    return &m_urlList;
}


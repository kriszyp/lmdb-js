/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_MESSAGE_QUEUE_H
#define LDAP_MESSAGE_QUEUE_H

#include <stack>

#include "LDAPUrlList.h"

class LDAPAsynConnection;
class LDAPMsg;
class LDAPRequest;
class LDAPSearchRequest;
class LDAPUrl;
typedef stack<LDAPRequest*> LDAPRequestStack;
typedef list<LDAPRequest*> LDAPRequestList;

class LDAPMessageQueue{
    public :
        LDAPMessageQueue(LDAPRequest *conn);
        ~LDAPMessageQueue();
        LDAPMsg* getNext();
        LDAPRequest* chaseReferral(LDAPMsg* ref);
        LDAPRequestStack* getRequestStack(); 
    
    private :
        LDAPRequestStack m_activeReq;
        LDAPRequestList m_issuedReq;
};
#endif //ifndef LDAP_MESSAGE_QUEUE_H


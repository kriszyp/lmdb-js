/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPMessageQueue.h,v 1.10 2000/08/31 17:43:49 rhafer Exp $

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

class LDAPMessageQueue{
    private :
        LDAPRequestStack m_reqQueue;
        void chaseReference(LDAPSearchRequest *req);
    public :
        LDAPMessageQueue(LDAPRequest *conn);
        ~LDAPMessageQueue();
        LDAPMsg* getNext();
        LDAPRequest* chaseReferral(LDAPUrlList *ref);
        LDAPRequestStack* getRequestStack(); 
};
#endif //ifndef LDAP_MESSAGE_QUEUE_H


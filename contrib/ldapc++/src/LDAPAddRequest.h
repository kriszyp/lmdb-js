/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_ADD_REQUEST_H
#define  LDAP_ADD_REQUEST_H

#include "LDAPRequest.h"
class LDAPMessageQueue;
class LDAPEntry;

class LDAPAddRequest : LDAPRequest {
    private:
        LDAPEntry *m_entry;

    public:
        LDAPAddRequest(const LDAPAddRequest& req);
        LDAPAddRequest(const LDAPEntry* entry, const LDAPAsynConnection *connect,
                const LDAPConstraints *cons, bool isReferral=false);
        virtual ~LDAPAddRequest();
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *refs);
};
#endif // LDAP_ADD_REQUEST_H


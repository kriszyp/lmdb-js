/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_EXT_REQUEST_H
#define LDAP_EXT_REQUEST_H

#include "LDAPRequest.h"

class LDAPExtRequest : LDAPRequest {

    private:
        char *m_oid;
        BerValue *m_data;
    public:
        LDAPExtRequest(const LDAPExtRequest& req);
        LDAPExtRequest(const char *oid, const BerValue *data, 
                const LDAPAsynConnection *connect, const LDAPConstraints *cons,
                bool isReferral=false);
        virtual ~LDAPExtRequest();
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *urls);
};

#endif // LDAP_EXT_REQUEST_H

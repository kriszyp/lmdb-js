/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_BIND_REQUEST_H
#define LDAP_BIND_REQUEST_H

#include "LDAPRequest.h"

class LDAPBindRequest : LDAPRequest {
    private:
        char *m_dn;
        BerValue *m_cred;
        char *m_mech;

    public:
        LDAPBindRequest(const LDAPBindRequest& req);
        //just for simple authentication
        LDAPBindRequest(const char *dn, const char *passwd, 
                const LDAPAsynConnection *connect, const LDAPConstraints *cons, 
                bool isReferral=false);
        virtual ~LDAPBindRequest();
        virtual LDAPMessageQueue *sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *urls);
};
#endif //LDAP_BIND_REQUEST_H


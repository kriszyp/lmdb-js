/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_BIND_REQUEST_H
#define LDAP_BIND_REQUEST_H

#include "LDAPRequest.h"

class LDAPBindRequest : LDAPRequest {
    private:
        string m_dn;
        string m_cred;
        string m_mech;

    public:
        LDAPBindRequest(const LDAPBindRequest& req);
        //just for simple authentication
        LDAPBindRequest(const string&, const string& passwd, 
                LDAPAsynConnection *connect, const LDAPConstraints *cons, 
                bool isReferral=false);
        virtual ~LDAPBindRequest();
        virtual LDAPMessageQueue *sendRequest();
        virtual LDAPRequest* followReferral(LDAPMsg* urls);
};
#endif //LDAP_BIND_REQUEST_H


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_BIND_REQUEST_H
#define LDAP_BIND_REQUEST_H

#include <LDAPRequest.h>

class LDAPBindRequest : LDAPRequest {
    private:
        std::string m_dn;
        std::string m_cred;
        std::string m_mech;

    public:
        LDAPBindRequest(const LDAPBindRequest& req);
        //just for simple authentication
        LDAPBindRequest(const std::string&, const std::string& passwd, 
                LDAPAsynConnection *connect, const LDAPConstraints *cons, 
                bool isReferral=false);
        virtual ~LDAPBindRequest();
        virtual LDAPMessageQueue *sendRequest();
        virtual LDAPRequest* followReferral(LDAPMsg* urls);
};
#endif //LDAP_BIND_REQUEST_H


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_COMPARE_REQUEST_H
#define LDAP_COMPARE_REQUEST_H

#include "LDAPRequest.h"

class LDAPMessageQueue;

class LDAPCompareRequest : public LDAPRequest {
    private :
        char *m_dn;
        LDAPAttribute *m_attr;
        
    public :
        LDAPCompareRequest(const LDAPCompareRequest& req);
        LDAPCompareRequest(const char* dn, const LDAPAttribute* attr, 
                const LDAPAsynConnection *connect, const LDAPConstraints *cons,
                bool isReferral=false);
        virtual ~LDAPCompareRequest();
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *urls);
};
#endif //LDAP_COMPARE_REQUEST_H



/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_MOD_DN_REQUEST_H
#define LDAP_MOD_DN_REQUEST_H

#include "LDAPRequest.h"

class LDAPModDNRequest : LDAPRequest {
    private:
        char *m_dn;
        char *m_newRDN;
        char *m_newParentDN;
        bool m_deleteOld;

    public:
        LDAPModDNRequest(const LDAPModDNRequest& req); 
        LDAPModDNRequest(const char *dn, const char *newRDN, bool deleteOld, 
                const char *newParentDN, const LDAPAsynConnection *connect,
                const LDAPConstraints *cons, bool isReferral=false); 
        virtual ~LDAPModDNRequest(); 
        
        virtual LDAPMessageQueue* sendRequest(); 
        virtual LDAPRequest* followReferral(LDAPUrlList* urls);
};    

#endif // LDAP_MOD_DN_REQUEST_H


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_MOD_DN_REQUEST_H
#define LDAP_MOD_DN_REQUEST_H

#include "LDAPRequest.h"

class LDAPModDNRequest : LDAPRequest {

    public:
        LDAPModDNRequest(const LDAPModDNRequest& req); 
        LDAPModDNRequest(const string& dn, const string& newRDN,
                bool deleteOld, const string& newParentDN,
                LDAPAsynConnection *connect, const LDAPConstraints *cons,
                bool isReferral=false, const LDAPRequest* parent=0); 
        virtual ~LDAPModDNRequest(); 
        
        virtual LDAPMessageQueue* sendRequest(); 
        virtual LDAPRequest* followReferral(LDAPMsg*  urls);
    
    private:
        string m_dn;
        string m_newRDN;
        string m_newParentDN;
        bool m_deleteOld;
};    

#endif // LDAP_MOD_DN_REQUEST_H


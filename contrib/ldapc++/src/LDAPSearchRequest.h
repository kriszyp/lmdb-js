/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_SEARCH_REQUEST_H
#define LDAP_SEARCH_REQUEST_H

#include <queue>
#include "LDAPRequest.h"

class LDAPSearchReference;
class LDAPReferral;
class LDAPUrl;

class LDAPSearchRequest : public LDAPRequest{ 
    private :
        const char *m_base;
        int m_scope;
        const char *m_filter;
        char **m_attrs;

        //no default constructor
        LDAPSearchRequest();

    public :
        LDAPSearchRequest(const LDAPSearchRequest& req);

        LDAPSearchRequest(const char *base, int scope, const char* filter,
                          char **attrs, const LDAPAsynConnection *connect,
                          const LDAPConstraints* cons, bool isReferral=false);
        virtual ~LDAPSearchRequest();        
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *ref);
};

#endif //LDAP_SEARCH_REQUEST_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_SEARCH_REFERENCE_H
#define LDAP_SEARCH_REFERENCE_H 

#include "LDAPMessage.h"
#include "LDAPUrlList.h"

class LDAPRequest;
class LDAPUrl;

class LDAPSearchReference : public LDAPMsg{

    public :
        LDAPSearchReference(const LDAPRequest* req, LDAPMessage* msg);
        ~LDAPSearchReference();
        const LDAPUrlList& getUrls() const;

    private :
        LDAPUrlList m_urlList;
        LDAPSearchReference();
};



#endif //LDAP_SEARCH_REFERENCE_H

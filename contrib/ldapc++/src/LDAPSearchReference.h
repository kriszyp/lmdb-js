/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPSearchReference.h,v 1.7 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_SEARCH_REFERENCE_H
#define LDAP_SEARCH_REFERENCE_H 

#include "LDAPMessage.h"
#include "LDAPUrlList.h"

class LDAPRequest;
class LDAPUrl;

class LDAPSearchReference : public LDAPMsg{

    private :
        LDAPUrlList m_urlList;
        LDAPSearchReference();

    public :
        LDAPSearchReference(LDAPRequest* req, LDAPMessage* msg);
        ~LDAPSearchReference();
        LDAPUrlList* getURLs();
};



#endif //LDAP_SEARCH_REFERENCE_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_REFERRAL_EXCEPTION_H
#define LDAP_REFERRAL_EXCEPTION_H

#include <list>
#include "LDAPMessage.h"
#include "LDAPUrlList.h"

class LDAPUrlList;

class LDAPReferralException : public LDAPException{

    private :
        LDAPUrlList m_urlList;

    public :
        LDAPReferralException(const LDAPUrlList& urls);
        ~LDAPReferralException();
        const LDAPUrlList& getUrls();
};

#endif //LDAP_REFERRAL_EXCEPTION_H

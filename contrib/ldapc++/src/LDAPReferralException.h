/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_REFERRAL_EXCEPTION_H
#define LDAP_REFERRAL_EXCEPTION_H

#include <list>
#include <LDAPMessage.h>
#include <LDAPUrlList.h>

class LDAPUrlList;

/**
 * This class extends LDAPException and is used to signalize Referrals
 * there were received during synchronous LDAP-operations
 */
class LDAPReferralException : public LDAPException{

    public :
        /**
         * Creates an object that is initialized with a list of URLs
         */
        LDAPReferralException(const LDAPUrlList& urls);

        /**
         * Destructor
         */
        ~LDAPReferralException();

        /**
         * @return The List of URLs of the Referral/Search Reference
         */
        const LDAPUrlList& getUrls();

    private :
        LDAPUrlList m_urlList;
};

#endif //LDAP_REFERRAL_EXCEPTION_H

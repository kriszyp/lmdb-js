/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPReferral.h,v 1.8 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_REFERRAL_H
#define LDAP_REFERRAL_H

#include <list>
#include "LDAPMessage.h"

class LDAPRequest;
class LDAPUrl;


class LDAPReferral {

    private :
        LDAPUrlList m_urlList;

    public :
        LDAPReferral();
        ~LDAPReferral();
        LDAPUrl* getURL();
};

#endif //LDAP_REFERRAL_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include <iostream>
#include "LDAPException.h"
#include "LDAPReferralException.h"
#include "LDAPResult.h"
#include "LDAPRequest.h"
#include "LDAPUrl.h"

LDAPReferralException::LDAPReferralException(const LDAPUrlList& urls) : 
        LDAPException(LDAPResult::REFERRAL) , m_urlList(urls){
}

LDAPReferralException::~LDAPReferralException(){
}

const LDAPUrlList& LDAPReferralException::getUrls(){
    return m_urlList;
}


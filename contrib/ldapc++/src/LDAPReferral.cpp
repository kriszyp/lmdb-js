/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPReferral.cpp,v 1.8 2000/08/31 17:43:49 rhafer Exp $

#include <iostream>
#include "LDAPException.h"
#include "LDAPReferral.h"
#include "LDAPRequest.h"
#include "LDAPUrl.h"

LDAPReferral::LDAPReferral() {
}

LDAPReferral::~LDAPReferral(){
    LDAPUrlList::const_iterator i;
    for(i=m_urlList.begin(); i!=m_urlList.end(); i++){
        delete *i;
    }
}

LDAPUrl* LDAPReferral::getURL(){
    return m_urlList.front();
}


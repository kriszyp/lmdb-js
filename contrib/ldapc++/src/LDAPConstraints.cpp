/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPConstraints.cpp,v 1.10 2000/08/31 17:43:48 rhafer Exp $

#include "debug.h"
#include "LDAPConstraints.h"
//#include "LDAPAsynConnection.h"

LDAPConstraints::LDAPConstraints(){
	m_maxTime=LDAP_NO_LIMIT;
	m_maxSize=LDAP_NO_LIMIT;
	m_referralChase=true;
}

LDAPConstraints::LDAPConstraints(const LDAPConstraints& c){
    m_maxTime=c.m_maxTime;
    m_maxSize=c.m_maxSize;
    m_referralChase=c.m_referralChase;
}

LDAPConstraints::~LDAPConstraints(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConstraints::~LDAPConstraints()" << endl);
}

void LDAPConstraints::setMaxTime(int t){
	m_maxTime=t;
}

void LDAPConstraints::setSizeLimit(int s){
	m_maxSize=s;
}

void LDAPConstraints::setReferralChase(bool rc){
}

int LDAPConstraints::getMaxTime() const {
	return m_maxTime;
}

int LDAPConstraints::getSizeLimit() const {
	return m_maxSize;
}

//TODO
LDAPControl** LDAPConstraints::getSrvCtrlsArray() const {
    return 0;
}

//TODO
LDAPControl** LDAPConstraints::getClCtrlsArray() const {
    return 0;
}

timeval* LDAPConstraints::getTimeoutStruct() const {
    if(m_maxTime == LDAP_NO_LIMIT){
        return 0;
    }else{
        timeval *ret = new timeval;
        ret->tv_sec=m_maxTime;
        ret->tv_usec=0;
        return ret;
    }
}

bool LDAPConstraints::getReferralChase() const {
	return m_referralChase;
}


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPResult.cpp,v 1.10 2000/08/31 17:43:49 rhafer Exp $

#include "debug.h"
#include"LDAPResult.h"
#include"LDAPAsynConnection.h"
#include "LDAPRequest.h"

LDAPResult::LDAPResult(LDAPRequest *req, LDAPMessage *msg) : LDAPMsg(msg){
	if(msg != 0){
        DEBUG(LDAP_DEBUG_TRACE,"LDAPResult::LDAPResult()" << endl);
        const LDAPAsynConnection *con=req->getConnection();

        //TODO!!:
        //handle referrals and controls
        char **refs=0;
		ldap_parse_result(con->getSessionHandle(),msg,&m_resCode,
				&m_matchedDN, &m_errMsg,&refs,0,0);
        if (refs != 0){
            for (char **tmp=refs;*tmp != 0; tmp++){
                DEBUG(LDAP_DEBUG_PARAMETER,"   url:" << *tmp << endl);
            }
        }
	}
}

LDAPResult::~LDAPResult(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPResult::~LDAPResult()" << endl);
    delete[] m_matchedDN;
    delete[] m_errMsg;
}

int LDAPResult::getResultCode(){
    return m_resCode;
}

char* LDAPResult::resToString(){
    return ldap_err2string(m_resCode);
}

char* LDAPResult::getErrMsg(){
    return strdup(m_errMsg);
}

char* LDAPResult::getMatchedDN(){
    return strdup(m_matchedDN);
}

ostream& operator<<(ostream &s,LDAPResult &l){
	return s << "Result: " << l.m_resCode << ": "  
        << ldap_err2string(l.m_resCode) << endl 
        << "Matched: " << l.m_matchedDN << endl << "ErrMsg: " << l.m_errMsg;
}


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPResult.h,v 1.7 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_RESPNSE_H
#define LDAP_RESPONSE_H

#include<iostream>
#include<ldap.h>
#include "LDAPMessage.h"

class LDAPRequest;
class LDAPAsynConnection;
class LDAPResult : public LDAPMsg{
	private :
		int m_resCode;
		char *m_matchedDN;
		char *m_errMsg;
	
	public :
        static const int SUCCESS=0;
        static const int REFERRAL=10;

		LDAPResult(LDAPRequest *req, LDAPMessage *msg);
        virtual ~LDAPResult();
		int getResultCode();
		char* resToString();
		char* getErrMsg();
		char* getMatchedDN();
		friend  ostream& operator<<(ostream &s,LDAPResult &l);
};
#endif //LDAP_RESPONSE_H


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_DELETE_REQUEST_H
#define LDAP_DELETE_REQUEST_H

#include "LDAPRequest.h"
class LDAPMessageQueue;

class LDAPDeleteRequest : public LDAPRequest{
	private :
		char *m_dn;
    public :
        LDAPDeleteRequest(const LDAPDeleteRequest& req);
        LDAPDeleteRequest(const char *dn, const LDAPAsynConnection *connect,
                const LDAPConstraints *cons, bool isReferral=false);
        virtual ~LDAPDeleteRequest();
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *refs); 
};
#endif //LDAP_DELETE_REQUEST_H

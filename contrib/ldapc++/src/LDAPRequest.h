/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPRequest.h,v 1.11 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_REQUEST_H
#define LDAP_REQUEST_H

#include "LDAPConstraints.h"
#include "LDAPAsynConnection.h"
#include "LDAPMessageQueue.h"

class LDAPUrl;

//!virtual class for Requests
class LDAPRequest{
        
    protected :
        bool m_isReferral;
        int m_requestType;
        LDAPConstraints *m_cons;
        const LDAPAsynConnection *m_connection;
        int m_msgID;  //the associated C-API Message ID
        LDAPRequest();

    public :
        LDAPRequest(const LDAPRequest& req);
        LDAPRequest(const LDAPAsynConnection* conn, const LDAPConstraints* cons, 
                bool isReferral=false);
        virtual ~LDAPRequest();
        virtual LDAPMessageQueue* sendRequest()=0;
        virtual LDAPRequest* followReferral(LDAPUrlList *ref)=0;
        const LDAPConstraints* getConstraints();
        const LDAPAsynConnection* getConnection();
        int getType()const;
        int getMsgID() const;
        bool isReferral() const;
        bool doRebind() const; 

        static const int BIND=0;
        static const int UNBIND=2;
        static const int SEARCH=3;
        static const int MODIFY=7;
        static const int ADD=8;
		static const int DELETE=10;
        static const int COMPARE=14;
};
#endif //LDAP_REQUEST_H 


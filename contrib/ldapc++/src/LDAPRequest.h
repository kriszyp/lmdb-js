/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_REQUEST_H
#define LDAP_REQUEST_H

#include "LDAPConstraints.h"
#include "LDAPAsynConnection.h"
#include "LDAPMessageQueue.h"

class LDAPUrl;

//!virtual class for Requests
class LDAPRequest{

    public :
        static const int BIND=0;
        static const int UNBIND=2;
        static const int SEARCH=3;
        static const int MODIFY=7;
        static const int ADD=8;
		static const int DELETE=10;
        static const int COMPARE=14;

        LDAPRequest(const LDAPRequest& req);
        LDAPRequest(LDAPAsynConnection* conn, 
                const LDAPConstraints* cons, bool isReferral=false,
                const LDAPRequest* parent=0);
        virtual ~LDAPRequest();
        
        const LDAPConstraints* getConstraints() const;
        const LDAPAsynConnection* getConnection() const;
        int getType()const;
        int getMsgID() const;
        int getHopCount() const;
        const LDAPRequest* getParent() const;

        bool isReferral() const;
        void unbind() const; 
        virtual LDAPMessageQueue* sendRequest()=0;
        virtual LDAPRequest* followReferral(LDAPMsg* ref)=0;
        virtual bool equals(const LDAPRequest* req) const;
        bool isCycle() const;
        
    protected :
        bool m_isReferral;
        int m_requestType;
        LDAPConstraints *m_cons;
        LDAPAsynConnection *m_connection;
        const LDAPRequest* m_parent;
        int m_hopCount;
        int m_msgID;  //the associated C-API Message ID
        LDAPRequest();
};
#endif //LDAP_REQUEST_H 


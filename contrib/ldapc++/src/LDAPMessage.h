/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_MSG_H
#define LDAP_MSG_H
#include <ldap.h>

#include "LDAPControlSet.h"

class LDAPRequest;
//! Represents an LDAPMsg returned from the server
/*!
 * This class is normally not instantiated directly. Normally only
 * its subclasses are used. The main feature of this class is the
 * static method create() (see below)
 */
class LDAPMsg{
	public:
        //public Constants defining the Message types
        static const int BIND_RESPONSE=LDAP_RES_BIND;
        static const int SEARCH_ENTRY=LDAP_RES_SEARCH_ENTRY;
        static const int SEARCH_DONE=LDAP_RES_SEARCH_RESULT;
        static const int SEARCH_REFERENCE=LDAP_RES_SEARCH_REFERENCE;
        static const int MODIFY_RESPONSE=LDAP_RES_MODIFY;
        static const int ADD_RESPONSE=LDAP_RES_ADD;
        static const int DEL_RESPONSE=LDAP_RES_DELETE;
        static const int MODDN_RESPONSE=LDAP_RES_MODDN;
        static const int COMPARE_RESPONSE=LDAP_RES_COMPARE;
        static const int EXTENDED_RESPONSE=LDAP_RES_EXTENDED;
        
		virtual ~LDAPMsg() {}

		/*!
		 * Based on msgtype-Value of the *msg-Parameter this method creates
		 * an Object of one of the subtypes of LDAPMsg (e.g. LDAPSearchResult
         * or LDAPResult) that represents the same Message as the
         * *msg-Parameter. *msg is e.g. a Message returned by the C-API's
         * ldap_result call.
		 */
		static LDAPMsg* create(const LDAPRequest *req, LDAPMessage *msg);	
		int getMessageType();
        int getMsgID();
        bool hasControls() const;
        const LDAPControlSet& getSrvControls() const;
	
    protected:
		LDAPMsg(LDAPMessage *msg);
        LDAPControlSet m_srvControls;
        bool m_hasControls;

	private:
		int msgType;
		int msgID;
};
#endif //ifndef LDAP_MSG_H

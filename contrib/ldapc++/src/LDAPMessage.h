/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPMessage.h,v 1.7 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_MSG_H
#define LDAP_MSG_H
#include <ldap.h>

//#include "LDAPConnection.h"

class LDAPRequest;
//! Represents an LDAPMsg returned from the server
/*!
 * This class is normally not instantiated directly. Normally only
 * its subclasses are used. The main feature of this class is the
 * static method create() (see below)
 */
class LDAPMsg{
	private:
		int msgID;
	protected:
		int msgType;
		LDAPMsg(LDAPMessage *msg);

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
		static LDAPMsg* create(LDAPRequest *req, LDAPMessage *msg);	
		int getMessageType();
        int getMsgID();
};
#endif //ifndef LDAP_MSG_H

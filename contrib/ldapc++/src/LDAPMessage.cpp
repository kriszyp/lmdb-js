/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPMessage.cpp,v 1.6 2000/08/31 17:43:48 rhafer Exp $

#include "LDAPMessage.h"
#include "LDAPResult.h"
#include "LDAPRequest.h"
#include "LDAPSearchResult.h"
#include "LDAPSearchReference.h"
#include "debug.h"
#include <iostream>

LDAPMsg::LDAPMsg(LDAPMessage *msg){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPMsg::LDAPMsg()" << endl);
	msgType=ldap_msgtype(msg);
}

LDAPMsg* LDAPMsg::create(LDAPRequest *req, LDAPMessage *msg){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPMsg::create()" << endl);
	switch(ldap_msgtype(msg)){
		case LDAP_RES_SEARCH_ENTRY :
			return new LDAPSearchResult(req,msg);
		break;
		case LDAP_RES_SEARCH_REFERENCE :
			return new LDAPSearchReference(req, msg);
		break;
		default :
			return new LDAPResult(req, msg);
	}
	return 0;
}


int LDAPMsg::getMessageType(){
	return msgType;
}

int LDAPMsg::getMsgID(){
	return msgID;
}


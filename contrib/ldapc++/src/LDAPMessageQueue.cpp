/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPMessageQueue.cpp,v 1.17 2000/08/31 17:43:48 rhafer Exp $

#include "config.h"
#include "debug.h"
#include <ldap.h>
#include "LDAPMessageQueue.h"
#include "LDAPRequest.h"
#include "LDAPAsynConnection.h"
#include "LDAPMessage.h"
#include "LDAPResult.h"
#include "LDAPSearchReference.h"
#include "LDAPSearchRequest.h"
#include "LDAPUrl.h"
#include "LDAPUrlList.h"
#include "LDAPException.h"

// TODO: How to handel unsolicited notifications, like notice of
//       disconnection

LDAPMessageQueue::LDAPMessageQueue(LDAPRequest *req){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPMessageQueue::LDAPMessageQueue()" << endl);
	m_reqQueue.push(req);
}

LDAPMessageQueue::~LDAPMessageQueue(){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPMessageQueue::~LDAPMessageQueue()" << endl);
    LDAPRequest *req;
    while(! m_reqQueue.empty()){
        req=m_reqQueue.top();
        delete req;
        m_reqQueue.pop();
    }
}

LDAPMsg *LDAPMessageQueue::getNext(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPMessageQueue::getNext()" << endl);
	LDAPMessage *msg;
    LDAPRequest *req=m_reqQueue.top();
    const LDAPConstraints *constr=req->getConstraints();
    int msg_id = req->getMsgID();
	int res;
    const  LDAPAsynConnection *con=req->getConnection();
	res=ldap_result(con->getSessionHandle(),msg_id,0,0,&msg);
	if (res <= 0){
        ldap_msgfree(msg);
		throw  LDAPException(con);
	}else{	
		LDAPMsg *ret = LDAPMsg::create(req,msg);
        ldap_msgfree(msg);
        switch (ret->getMessageType()) {
            case LDAPMsg::SEARCH_REFERENCE : 
                if (constr->getReferralChase() ){
                    LDAPSearchReference *ref=(LDAPSearchReference *)ret;
                    LDAPRequest *refReq=chaseReferral(ref->getURLs());
                    if(refReq != 0){
                        m_reqQueue.push(refReq);
                        return getNext();
                    }
                }
                return ret;
            break;
            case LDAPMsg::SEARCH_ENTRY :
                return ret;
            break;
            case LDAPMsg::SEARCH_DONE :
                if (req->isReferral()){
                    LDAPResult* res_p=(LDAPResult*)ret;
                    switch (res_p->getResultCode()) {
                        case LDAPResult::REFERRAL :
                            DEBUG(LDAP_DEBUG_TRACE, 
                                    "referral chasing to be implemented" 
                                    << endl);
                            return ret;
                        break;
                        default:
                            return ret;
                    }
                    delete req;
                    m_reqQueue.pop();
                    return getNext();
                }else{
                    return ret;
                }
            break;
            //must be some kind of LDAPResultMessage
            default:
                LDAPResult* res_p=(LDAPResult*)ret;
                switch (res_p->getResultCode()) {
                    case LDAPResult::REFERRAL :
                        DEBUG(LDAP_DEBUG_TRACE, 
                               "referral chasing to be implemented" 
                                << endl);
                        //for now just end it here
                        delete req;
                        return ret;
                    break;
                    default:
                        delete req;
                        m_reqQueue.pop();
                        return ret;
                }
            break;
        }
	}	
}

// TODO Maybe moved to LDAPRequest::followReferral seems more reasonable
//there
LDAPRequest* LDAPMessageQueue::chaseReferral(LDAPUrlList *refs){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPMessageQueue::chaseReferra()" << endl);
    LDAPRequest *req=m_reqQueue.top();
    LDAPRequest *refReq=req->followReferral(refs);
    if(refReq !=0){
        try {
            refReq->sendRequest();
            return refReq;
        }catch (LDAPException e){
            cout << e << endl;
            DEBUG(LDAP_DEBUG_TRACE,"   caught exception" << endl);
            return 0;
        }
    }else{ 
        return 0;
    }
}

LDAPRequestStack* LDAPMessageQueue::getRequestStack(){
    return &m_reqQueue;
}


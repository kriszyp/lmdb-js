/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAsynConnection.cpp,v 1.3 2000/08/31 17:43:48 rhafer Exp $

#include "config.h"
#include "debug.h"
#include "LDAPAsynConnection.h"

#include "LDAPAddRequest.h"
#include "LDAPBindRequest.h"
#include "LDAPCompareRequest.h"
#include "LDAPDeleteRequest.h"
#include "LDAPException.h"
#include "LDAPExtRequest.h"
#include "LDAPEntry.h"
#include "LDAPModDNRequest.h"
#include "LDAPModifyRequest.h"
#include "LDAPRequest.h"
#include "LDAPSearchRequest.h"

LDAPAsynConnection::LDAPAsynConnection(const char *hostname, int port,
                               LDAPConstraints *cons ){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::LDAPAsynConnection()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   host:" << hostname << endl
            << "   port:" << port << endl);
    if (hostname!=0){
        this->init(hostname, port);
    }
    this->setConstraints(cons);
}


void LDAPAsynConnection::setConstraints(LDAPConstraints *cons){
    m_constr=cons;
}

LDAPConstraints* LDAPAsynConnection::getConstraints() const {
    return m_constr;
}
 
LDAPAsynConnection* LDAPAsynConnection::referralConnect(const LDAPUrlList* urls,
        LDAPUrl** usedUrl) const {
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAsynConnection::referralConnect()" << endl)
    LDAPUrlList::const_iterator conUrl;
    LDAPAsynConnection* tmpConn=0;
    for(conUrl=urls->begin(); conUrl!=urls->end(); conUrl++){
        char* host= (*conUrl)->getHost();
        int port= (*conUrl)->getPort();
        DEBUG(LDAP_DEBUG_TRACE,"   connecting to: " << host << ":" <<
                port << endl);
        tmpConn=new LDAPAsynConnection(host,port);
        // static bind here, to check for the result immediately and 
        // use the next URL if the bind fails;
        if( ldap_simple_bind_s(tmpConn->getSessionHandle(), 0,0) 
                == LDAP_SUCCESS ){
            *usedUrl=*conUrl;
            return tmpConn;
        }else{
            delete tmpConn;
            tmpConn=0;
        }
    }
    return 0;
}

void LDAPAsynConnection::init(const char *hostname, int port){
    cur_session=ldap_init(hostname,port);
    int opt=3;
    ldap_set_option(cur_session, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    ldap_set_option(cur_session, LDAP_OPT_PROTOCOL_VERSION, &opt);
}

LDAPMessageQueue* LDAPAsynConnection::bind(const char *dn, const char *passwd,
        const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAsynConnection::bind()" <<  endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl
               << "   passwd:" << passwd << endl);
    LDAPBindRequest *req = new LDAPBindRequest(dn,passwd,this,cons);
    LDAPMessageQueue *ret = req->sendRequest();
    return ret;
}

LDAPMessageQueue* LDAPAsynConnection::search(const char *base,int scope, 
                                         const char *filter, 
                                         char **attrs, 
                                         const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPAsynConnection::search()" <<  endl);
    DEBUG(LDAP_DEBUG_PARAMETER, "   base:" << base << endl
               << "   scope:" << scope << endl
               << "   filter:" << filter << endl );
    LDAPSearchRequest *req = new LDAPSearchRequest(base, scope,filter, attrs, 
                                              this, cons);
    LDAPMessageQueue* ret = req->sendRequest();
    return ret;
}

LDAPMessageQueue* LDAPAsynConnection::del(const char *dn, 
        const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::del()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   dn:" << dn << endl);
    LDAPDeleteRequest *req = new LDAPDeleteRequest(dn, this, cons);
    LDAPMessageQueue *ret= req->sendRequest();
    return ret;
}

LDAPMessageQueue* LDAPAsynConnection::compare(const char *dn, 
        const LDAPAttribute *attr, const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::compare()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   dn:" << dn << endl
            << "   attr:" << *attr << endl);
    LDAPCompareRequest *req = new LDAPCompareRequest(dn, attr, this, cons);
    LDAPMessageQueue *ret =  req->sendRequest();
    return ret;
}

LDAPMessageQueue* LDAPAsynConnection::add(LDAPEntry *le, 
        const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::add()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   entry:" << *le << endl);
    if (le == 0){
        return 0;
    }else{
        LDAPAddRequest *req = new LDAPAddRequest(le, this, cons);
        LDAPMessageQueue *ret = req->sendRequest();
        return ret;
    }
}

/*
LDAPMessageQueue* LDAPAsynConnection::modify(char *dn, LDAPModification *mod,
        const LDAPConstraints *cons){
    LDAPMod** m = new LDAPMod*[2];
    m[0]=mod->toLDAPMod();
    m[1]=0; 
    int msgq_id=ldap_modify(cur_session,dn,m,cons);
    if (msgq_id <= 0){
        throw LDAPException(this);
    }else{
        return new LDAPMessageQueue(msgq_id,this);
    }
}
*/

LDAPMessageQueue* LDAPAsynConnection::modify(const char *dn, LDAPModList *mod,
        const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::modify()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   dn:" << dn << endl);
    LDAPModifyRequest *req = new LDAPModifyRequest(dn, mod, this, cons);
    LDAPMessageQueue *ret = req->sendRequest();
    return ret;
}

LDAPMessageQueue* LDAPAsynConnection::rename(const char *dn, const char *newRDN, 
        bool delOldRDN, const char *newParentDN, const LDAPConstraints *cons ){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::rename()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   dn:" << dn << endl
            << "   newRDN:" << newRDN << endl
            << "   newParentDN:" << newParentDN << endl
            << "   delOldRDN:" << delOldRDN << endl);
    LDAPModDNRequest *req = new  LDAPModDNRequest(dn, newRDN, delOldRDN, 
            newParentDN, this, cons );
    LDAPMessageQueue *ret = req->sendRequest();
    return ret;
}


LDAPMessageQueue* LDAPAsynConnection::extOperation(const char* oid, 
        BerValue* value, const LDAPConstraints *cons ){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::extOperation()" << endl);
    DEBUG(LDAP_DEBUG_PARAMETER,"   oid:" << oid << endl);
    if (oid == 0){
        return 0;
    }else{
        LDAPExtRequest *req = new  LDAPExtRequest(oid, value, this,cons);
        LDAPMessageQueue *ret = req->sendRequest();
        return ret;
    }
}


void LDAPAsynConnection::abandon(LDAPMessageQueue *q){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAsynConnection::*extOperation()" << endl);
    LDAPRequestStack *reqStack=q->getRequestStack();
    LDAPRequest *req;
    while(! reqStack->empty()){
        req=reqStack->top();
        if (ldap_abandon_ext(cur_session, req->getMsgID(), 0, 0) 
                != LDAP_SUCCESS){
            throw LDAPException(this);
        }
        delete req;
        reqStack->pop();
    }
}


LDAP* LDAPAsynConnection::getSessionHandle() const {
    return cur_session;
}


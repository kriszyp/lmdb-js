/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include <ldap.h>

#include "debug.h"

#include "LDAPBindRequest.h"
#include "LDAPException.h"

using namespace std;

LDAPBindRequest::LDAPBindRequest(const LDAPBindRequest& req) :
        LDAPRequest(req){
    DEBUG(LDAP_DEBUG_CONSTRUCT, "LDAPBindRequest::LDAPBindRequest(&)" << endl);
    m_dn=req.m_dn;
    m_cred=req.m_cred;
    m_mech=req.m_mech;
}

LDAPBindRequest::LDAPBindRequest(const string& dn,const string& passwd, 
        LDAPAsynConnection *connect, const LDAPConstraints *cons,
        bool isReferral=false) : LDAPRequest(connect, cons, isReferral){
   DEBUG(LDAP_DEBUG_CONSTRUCT,"LDAPBindRequest::LDAPBindRequest()" << endl);
   DEBUG(LDAP_DEBUG_CONSTRUCT | LDAP_DEBUG_PARAMETER, "   dn:" << dn << endl
           << "   passwd:" << passwd << endl);
    m_dn = dn;
    m_cred = passwd;
    m_mech = "";
}

LDAPBindRequest::~LDAPBindRequest(){
    DEBUG(LDAP_DEBUG_DESTROY,"LDAPBindRequest::~LDAPBindRequest()" << endl);
}

LDAPMessageQueue* LDAPBindRequest::sendRequest(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::sendRequest()" << endl);
    int msgID=0;
    
    const char* mech = (m_mech == "" ? 0 : m_mech.c_str());
    BerValue* tmpcred=0;
    if(m_cred != ""){
        char* tmppwd = (char*) malloc( (m_cred.size()+1) * sizeof(char));
        m_cred.copy(tmppwd,string::npos);
        tmppwd[m_cred.size()]=0;
        tmpcred=ber_bvstr(tmppwd);
    }else{
        tmpcred=(BerValue*) malloc(sizeof(BerValue));
        tmpcred->bv_len=0;
        tmpcred->bv_val=0;
    }
    const char* dn = 0;
    if(m_dn != ""){
        dn = m_dn.c_str();
    }
    LDAPControl** tmpSrvCtrls=m_cons->getSrvCtrlsArray();
    LDAPControl** tmpClCtrls=m_cons->getClCtrlsArray();
    int err=ldap_sasl_bind(m_connection->getSessionHandle(),dn, 
            mech, tmpcred, tmpSrvCtrls, tmpClCtrls, &msgID);
    LDAPControlSet::freeLDAPControlArray(tmpSrvCtrls);
    LDAPControlSet::freeLDAPControlArray(tmpClCtrls);
    ber_bvfree(tmpcred);

    if(err != LDAP_SUCCESS){
        throw LDAPException(err);
    }else{
        m_msgID=msgID;
        return new LDAPMessageQueue(this);
    }
}

LDAPRequest* LDAPBindRequest::followReferral(LDAPMsg* /*urls*/){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPBindRequest::followReferral()" << endl);
    DEBUG(LDAP_DEBUG_TRACE,
            "ReferralChasing for bind-operation not implemented yet" << endl);
    return 0;
}


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */



#include <ldap.h>
#include "config.h"
#include "LDAPException.h"
#include "LDAPReferralException.h"

#include "LDAPAsynConnection.h"

using namespace std;

LDAPException::LDAPException(int res_code, const string& err_string){
	m_res_code=res_code;
	m_res_string=string(ldap_err2string(res_code));
    m_err_string=err_string;
}

LDAPException::LDAPException(const LDAPAsynConnection *lc){
	m_err_string=string();
	m_res_string=string();
	LDAP *l = lc->getSessionHandle();
	ldap_get_option(l,LDAP_OPT_ERROR_NUMBER,&m_res_code);
	m_res_string=string(ldap_err2string(m_res_code));
    char* err_string;
	ldap_get_option(l,LDAP_OPT_ERROR_STRING,&err_string);
    m_err_string=string(err_string);
}

LDAPException::~LDAPException(){
}

int LDAPException::getResultCode() const{
	return m_res_code;
}

const string& LDAPException::getResultMsg() const{
	return m_res_string;
}

const string& LDAPException::getServerMsg() const{
    return m_err_string;
}

ostream& operator << (ostream& s, LDAPException e){
	s << "Error " << e.m_res_code << ": " << e.m_res_string;
	if (!e.m_err_string.empty()) {
		s << endl <<  "additional info: " << e.m_err_string ;
	}
	return s;
}


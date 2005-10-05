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
    LDAP *l = lc->getSessionHandle();
    ldap_get_option(l,LDAP_OPT_ERROR_NUMBER,&m_res_code);
    const char *res_cstring = ldap_err2string(m_res_code);
    if ( res_cstring ) {
        m_res_string = string(res_cstring);
    } else {
        m_res_string = "";
    }
    const char* err_string;
    ldap_get_option(l,LDAP_OPT_ERROR_STRING,&err_string);
    if ( err_string ) {
        m_res_string = string(err_string);
    } else {
        m_res_string = "";
    }
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


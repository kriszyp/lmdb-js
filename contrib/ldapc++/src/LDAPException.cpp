/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPException.cpp,v 1.7 2000/08/31 17:43:48 rhafer Exp $


#include <ldap.h>
#include "config.h"
#include "ac/string.h"
#include "LDAPException.h"

LDAPException::LDAPException(int res_code, char *err_string=0){
	m_res_code=res_code;
	m_res_string=ldap_err2string(res_code);
	if(err_string != 0){
        m_err_string=strdup(err_string);
    }else{
        m_err_string=0;
    }
}

LDAPException::LDAPException(const LDAPAsynConnection *lc){
	m_err_string=0;
	m_res_string=0;
	LDAP *l = lc->getSessionHandle();
	ldap_get_option(l,LDAP_OPT_ERROR_NUMBER,&m_res_code);
	m_res_string=ldap_err2string(m_res_code);
	ldap_get_option(l,LDAP_OPT_ERROR_STRING,&m_err_string);
}

int LDAPException::getResultCode(){
	return m_res_code;
}

char* LDAPException::getResultMsg(){
	return strdup(m_res_string);
}

ostream& operator << (ostream& s, LDAPException e){
	s << "Error " << e.m_res_code << ": " << e.m_res_string;
	if (e.m_err_string != 0) {
		s << endl <<  "additional info: " << e.m_err_string ;
	}
	return s;
}


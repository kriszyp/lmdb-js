/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_EXCEPTION_H
#define LDAP_EXCEPTION_H

#include <iostream>
#include <string>

class LDAPAsynConnection;

class LDAPException{

	private :
		int m_res_code;
		string m_res_string;
		string m_err_string;
		
	public :
		LDAPException(int res_code, const string& err_string=string());
		LDAPException(const LDAPAsynConnection *lc);
        virtual ~LDAPException();
		int getResultCode() const;
		const string& getResultMsg() const;
		friend ostream& operator << (ostream &s, LDAPException e);
};
#endif //LDAP_EXCEPTION_H

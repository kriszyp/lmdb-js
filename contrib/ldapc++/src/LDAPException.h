/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPException.h,v 1.6 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_EXCEPTION_H
#define LDAP_EXCEPTION_H

#include <iostream>
#include "LDAPAsynConnection.h"

class LDAPException{

	private :
		int m_res_code;
		char* m_res_string;
		char* m_err_string;
		
	public :
		LDAPException(int res_code, char *err_string=0);
		LDAPException(const LDAPAsynConnection *lc);
		int getResultCode();
		char* getResultMsg();
		friend ostream& operator << (ostream &s, LDAPException e);
};
#endif //LDAP_EXCEPTION_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_CONTROL_H
#define LDAP_CONTROL_H
#include <string>
#include <ldap.h>


class LDAPCtrl{
	public :
        LDAPCtrl(const LDAPCtrl& c);
		LDAPCtrl(const char *oid, bool critical, const char *data=0, 
                int length=0);
        LDAPCtrl(const string& oid, bool critical=false,
                const string& data=string());
        LDAPCtrl(const LDAPControl* ctrl);
        ~LDAPCtrl();
        
        string getOID() const;
        string getData() const;
        bool isCritical() const;
        LDAPControl* getControlStruct() const;
	
    private :
        string m_oid;
        string m_data;
        bool m_isCritical;
};

#endif //LDAP_CONTROL_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_REBIND_AUTH_H
#define LDAP_REBIND_AUTH_H

#include<string>

class LDAPRebindAuth{
    public:
        LDAPRebindAuth(const string& dn="", const string& pwd="");
        LDAPRebindAuth(const LDAPRebindAuth& lra);
        virtual ~LDAPRebindAuth();

        const string& getDN() const;
        const string& getPassword() const;
        
    private:
        string m_dn;
        string m_password;
};

#endif //LDAP_REBIND_AUTH_H


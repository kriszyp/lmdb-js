/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_URL_H
#define LDAP_URL_H

#include <ldap.h>
#include "StringList.h"
class LDAPUrl{
    
    protected :
        int m_Port;
        int m_Scope;
        string m_Host;
        string m_DN;
        string m_Filter;
        StringList m_Attrs;
        LDAPURLDesc *m_urlDesc;
        string m_urlString;

    public : 
        LDAPUrl(const char *url);
        ~LDAPUrl();

        int getPort() const;
        int getScope() const;
        const string& getURLString() const;
        const string& getHost() const;
        const string& getDN() const;
        const string& getFilter() const;
        const StringList& getAttrs() const;
};

#endif //LDAP_URL_H

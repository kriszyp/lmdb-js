/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPUrl.h,v 1.5 2000/08/31 17:43:49 rhafer Exp $

#ifndef LDAP_URL_H
#define LDAP_URL_H

#include <ldap.h>

class LDAPUrl{
    
    protected :
        LDAPURLDesc *m_urlDesc;
        char *m_urlString;

    public : 
        LDAPUrl(char *url);
        LDAPUrl(char *host, int port, char *dn, char **attrs, int scope=0,
                char *filter=0);
        ~LDAPUrl();

        int getPort() const;
        int getScope() const;
        char* getURLString() const;
        char* getHost() const;
        char* getDN() const;
        char* getFilter() const;
        char** getAttrs() const;
};

#endif //LDAP_URL_H

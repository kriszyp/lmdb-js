/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_URL_H
#define LDAP_URL_H

#include <ldap.h>
#include <StringList.h>

/**
 * This class is used to analyze and store LDAP-Urls as returned by a
 * LDAP-Server as Referrals and Search References. LDAP-URLs are defined
 * in RFC1959 and have the following format: <BR>
 * <code>
 * ldap://host:port/baseDN[?attr[?scope[?filter]]] <BR>
 * </code>
 */
class LDAPUrl{

    public : 
        /**
         * Create a new object from a c-string that contains a LDAP-Url
         */
        LDAPUrl(const char *url);

        /**
         * Destructor
         */
        ~LDAPUrl();

        /**
         * @return The part of the URL that is representing the network
         * port
         */
        int getPort() const;

        /**
         * @return The scope part of the URL is returned. 
         */
        int getScope() const;

        /**
         * @return The complete URL as a string
         */
        const std::string& getURLString() const;

        /**
         * @return The hostname or IP-Address of the destination host.
         */
        const std::string& getHost() const;

        /**
         * @return The Base-DN part of the URL
         */
        const std::string& getDN() const;

        
        /**
         * @return The Filter part of the URL
         */
        const std::string& getFilter() const;

        /**
         * @return The List of attributes  that was in the URL
         */
        const StringList& getAttrs() const;
    
    protected :
        int m_Port;
        int m_Scope;
        std::string m_Host;
        std::string m_DN;
        std::string m_Filter;
        StringList m_Attrs;
        LDAPURLDesc *m_urlDesc;
        std::string m_urlString;
};

#endif //LDAP_URL_H

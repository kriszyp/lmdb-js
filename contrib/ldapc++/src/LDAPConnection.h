/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_CONNECTION_H
#define LDAP_CONNECTION_H

#include "LDAPSearchResults.h"

#include "LDAPAsynConnection.h" 

class LDAPConnection : private LDAPAsynConnection {

    public :
        static const int SEARCH_BASE;
        static const int SEARCH_ONE;
        static const int SEARCH_SUB;
        LDAPConnection(const string& hostname="localhost", int port=389,
                LDAPConstraints* cons=0);
        ~LDAPConnection();

        void init(const string& hostname, int port);
        void bind(const string& dn="", const string& passwd="",
                LDAPConstraints* cons=0);
        void unbind();
        bool compare(const string&, const LDAPAttribute& attr,
                LDAPConstraints* cons=0);
        void del(const string& dn, const LDAPConstraints* cons=0);
        void add(const LDAPEntry* le, const LDAPConstraints* cons=0);
        void modify(const string& dn, const LDAPModList* mods, 
                const LDAPConstraints* cons=0); 
        void rename(const string& dn, const string& newRDN, 
                bool delOldRDN=false, const string& newParentDN="",
                const LDAPConstraints* cons=0);
        LDAPSearchResults* search(const string& base, int scope=0, 
                const string& filter="objectClass=*", 
                const StringList& attrs=StringList(), bool attrsOnly=false,
                const LDAPConstraints* cons=0);

        const string& getHost() const;
        int getPort() const;
        void setConstraints(LDAPConstraints *cons);
        const LDAPConstraints* getConstraints() const ;
};

#endif //LDAP_CONNECTION_H

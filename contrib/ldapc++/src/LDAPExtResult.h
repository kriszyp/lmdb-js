/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_EXT_RESULT_H
#define LDAP_EXT_RESULT_H

#include <ldap.h>

class LDAPResult;
class LDAPRequest;

class LDAPExtResult : public LDAPResult {
    public :
        LDAPExtResult(const LDAPRequest* req, LDAPMessage* msg);
        virtual ~LDAPExtResult();

        const string& getResponseOid() const;
        const string& getResponse() const;

    private:
        string m_oid;
        string m_data;
};

#endif // LDAP_EXT_RESULT_H

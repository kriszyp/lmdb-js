/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_EXT_RESULT_H
#define LDAP_EXT_RESULT_H

#include <ldap.h>

#include <LDAPResult.h>

class LDAPRequest;

/**
 * Object of this class are created by the LDAPMsg::create method if
 * results for an Extended Operation were returned by a LDAP server.
 */
class LDAPExtResult : public LDAPResult {
    public :
        /**
         * Constructor that creates an LDAPExtResult-object from the C-API
         * structures
         */
        LDAPExtResult(const LDAPRequest* req, LDAPMessage* msg);

        /**
         * The Destructor
         */
        virtual ~LDAPExtResult();

        /**
         * @returns The OID of the Extended Operation that has returned
         *          this result. 
         */
        const string& getResponseOid() const;

        /**
         * @returns If the result contained data this method will return
         *          the data to the caller as a string.
         */
        const string& getResponse() const;

    private:
        string m_oid;
        string m_data;
};

#endif // LDAP_EXT_RESULT_H

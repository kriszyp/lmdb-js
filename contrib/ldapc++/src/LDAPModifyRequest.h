/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_MODIFY_REQUEST_H
#define LDAP_MODIFY_REQUEST_H

#include "LDAPRequest.h"

class LDAPMessageQueue;

class LDAPModifyRequest : LDAPRequest {
    private :
        char *m_dn;
        LDAPModList *m_modList;

    public:
        LDAPModifyRequest(const LDAPModifyRequest& mod);
        LDAPModifyRequest(const char *dn, const LDAPModList *modList,
                const LDAPAsynConnection *connect, const LDAPConstraints *cons,
                bool isReferral=false);
        virtual ~LDAPModifyRequest();
        virtual LDAPMessageQueue* sendRequest();
        virtual LDAPRequest* followReferral(LDAPUrlList *refs);
};

#endif // LDAP_MODIFY_REQUEST_H


/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_RESPNSE_H
#define LDAP_RESPONSE_H

#include<iostream>
#include<ldap.h>
#include "LDAPMessage.h"
#include "LDAPControlSet.h"
#include "LDAPUrlList.h"

class LDAPRequest;
class LDAPAsynConnection;

class LDAPResult : public LDAPMsg{
    public :
        //Error codes from RFC 2251
        static const int SUCCESS                        = 0;
        static const int OPERATIONS_ERROR               = 1;
        static const int PROTOCOL_ERROR                 = 2;
        static const int TIME_LIMIT_EXCEEDED            = 3;
        static const int SIZE_LIMIT_EXCEEDED            = 4;
        static const int COMPARE_FALSE                  = 5;
        static const int COMPARE_TRUE                   = 6;
        static const int AUTH_METHOD_NOT_SUPPORTED      = 7;
        static const int STRONG_AUTH_REQUIRED           = 8;
        
        static const int REFERRAL                       = 10;
        static const int ADMIN_LIMIT_EXCEEDED           = 11;
        static const int UNAVAILABLE_CRITICAL_EXTENSION = 12;
        static const int CONFIDENTIALITY_REQUIRED       = 13;
        static const int SASL_BIND_IN_PROGRESS          = 14;
        
        static const int NO_SUCH_ATTRIBUTE              = 16;
        static const int UNDEFINED_ATTRIBUTE_TYP        = 17;
        static const int INAPPROPRIATE_MATCHING         = 18;
        static const int CONSTRAINT_VIOLATION           = 19;
        static const int ATTRIBUTE_OR_VALUE_EXISTS      = 20;
        static const int INVALID_ATTRIBUTE_SYNTAX       = 21;
        
        static const int NO_SUCH_OBJECT                 = 32;
        static const int ALIAS_PROBLEM                  = 33;
        static const int INVALID_DN_SYNTAX              = 34;

        static const int ALIAS_DEREFERENCING_PROBLEM    = 36;

        static const int INAPPROPRIATE_AUTENTICATION    = 48;
        static const int INVALID_CREDENTIALS            = 49;
        static const int INSUFFICIENT_ACCESS            = 50;
        static const int BUSY                           = 51;
        static const int UNAVAILABLE                    = 52;
        static const int UNWILLING_TO_PERFORM           = 53;
        static const int LOOP_DETECT                    = 54;

        static const int NAMING_VIOLATION               = 64;
        static const int OBJECT_CLASS_VIOLATION         = 65;
        static const int NOT_ALLOWED_ON_NONLEAF         = 66;
        static const int NOT_ALLOWED_ON_RDN             = 67;
        static const int ENTRY_ALREADY_EXISTS           = 68;
        static const int OBJECT_CLASS_MODS_PROHIBITED   = 69;

        static const int AFFECTS_MULTIPLE_DSAS          = 71;
        
        // some Errorcodes defined in the LDAP C API DRAFT
        static const int OTHER                          = 80;
        static const int SERVER_DOWN                    = 81;
        static const int LOCAL_ERROR                    = 82;
        static const int ENCODING_ERROR                 = 83;
        static const int DECODING_ERROR                 = 84;
        static const int TIMEOUT                        = 85;
        static const int AUTH_UNKNOWN                   = 86;
        static const int FILTER_ERROR                   = 87;
        static const int USER_CANCELLED                 = 88;
        static const int PARAM_ERROR                    = 89;
        static const int NO_MEMORY                      = 90;
        static const int CONNECT_ERROR                  = 91;
        static const int NOT_SUPPORTED                  = 92;
        static const int CONTROL_NOT_FOUND              = 93;
        static const int NO_RESULTS_RETURNED            = 94;
        static const int MORE_RESULTS_TO_RETURN         = 95;
        static const int CLIENT_LOOP                    = 96;
        static const int REFERRAL_LIMIT_EXCEEDED        = 97;

        LDAPResult(const LDAPRequest *req, LDAPMessage *msg);
        virtual ~LDAPResult();
        int getResultCode() const;
        string resToString() const;
        const string& getErrMsg() const;
        const string& getMatchedDN() const;
        const LDAPUrlList& getReferralUrls() const;

    private :
        int m_resCode;
        string m_matchedDN;
        string m_errMsg;
        LDAPUrlList m_referrals;    

    friend  ostream& operator<<(ostream &s,LDAPResult &l);
};
#endif //LDAP_RESPONSE_H


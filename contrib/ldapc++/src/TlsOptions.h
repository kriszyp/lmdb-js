// $OpenLDAP$
/*
 * Copyright 2010, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef TLS_OPTIONS_H
#define TLS_OPTIONS_H
#include <string>
#include <ldap.h>

class TlsOptions {
    public:
        enum tls_option {
            CACERTFILE=0,
            CACERTDIR,
            CERTFILE,
            KEYFILE,
            REQUIRE_CERT,
            PROTOCOL_MIN,
            CIPHER_SUITE,
            RANDOM_FILE,
            CRLCHECK,
            DHFILE,
            LASTOPT /* dummy */
        };

        TlsOptions();
        void setOption(tls_option opt, const std::string& value) const;
        void setOption(tls_option opt, int value) const;
        void setOption(tls_option opt, void *value) const;

        int getIntOption(tls_option opt) const;
        std::string getStringOption(tls_option opt) const;
        void getOption(tls_option opt, void *value ) const;
        
        enum verifyMode {
            NEVER=0,
            HARD,
            DEMAND,
            ALLOW,
            TRY
        };

        enum crlMode {
            CRL_NONE=0,
            CRL_PEER,
            CRL_ALL
        };

    private:
        TlsOptions( LDAP* ld );
        void newCtx() const;
        LDAP *m_ld;

    friend class LDAPAsynConnection;
};

#endif /* TLS_OPTIONS_H */

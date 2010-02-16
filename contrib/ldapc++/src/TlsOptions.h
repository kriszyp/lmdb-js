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
            NEWCTX,
            LASTOPT /* dummy */
        };

        TlsOptions( LDAP* ld=NULL );
        void setOption(tls_option opt, const std::string& value);
        void setOption(tls_option opt, int value);
        void setOption(tls_option opt, void *value);

        int getIntOption(tls_option opt) const;
        std::string getStringOption(tls_option opt) const;
        void getOption(tls_option opt, void *value );
        
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
        LDAP *m_ld;        
};

#endif /* TLS_OPTIONS_H */

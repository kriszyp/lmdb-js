/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPUrl.cpp,v 1.6 2000/08/31 17:43:49 rhafer Exp $

#include "LDAPUrl.h"
#include <ldap.h>
#include <ac/string.h>
#include "debug.h"

LDAPUrl::LDAPUrl(char *url){
    DEBUG(LDAP_DEBUG_TRACE, "LDAPUrl::LDAPUrl()" << endl);
    if (ldap_is_ldap_url(url)){
        m_urlString = strdup(url);
        ldap_url_parse(url, &m_urlDesc);
    }else{
        DEBUG(LDAP_DEBUG_TRACE,"   noUrl:" << url << endl);
    }
}

LDAPUrl::LDAPUrl(char *host, int port, char *dn, char **attrs, int scope,
        char *filter){
    
}

LDAPUrl::~LDAPUrl(){
    delete[] m_urlString;
    ldap_free_urldesc(m_urlDesc);
}

int LDAPUrl::getPort() const {
    return m_urlDesc->lud_port;
}

int LDAPUrl::getScope() const {
    return m_urlDesc->lud_scope;
}

char* LDAPUrl::getURLString() const {
    return strdup(m_urlString);
}

char* LDAPUrl::getHost() const {
    return strdup(m_urlDesc->lud_host);
}

char* LDAPUrl::getDN() const {
    return strdup(m_urlDesc->lud_dn);
}

char* LDAPUrl::getFilter() const {
    return strdup(m_urlDesc->lud_filter);
}

char** LDAPUrl::getAttrs() const {
    size_t s;
    for ( char** i=m_urlDesc->lud_attrs; *i != 0; i++){
        s++;
    }
    char** ret=new char*[s+1];
    ret[s]=0;
    int j=0;
    for (char** i=m_urlDesc->lud_attrs; *i != 0; j++, i++){
        ret[j] = strdup(*i);
    }
    return ret;
}


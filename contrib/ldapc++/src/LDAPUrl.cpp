/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "LDAPUrl.h"

#include <ldap.h>
#include "debug.h"

using namespace std;

LDAPUrl::LDAPUrl(const char *url){
    DEBUG(LDAP_DEBUG_CONSTRUCT, "LDAPUrl::LDAPUrl()" << endl);
    DEBUG(LDAP_DEBUG_CONSTRUCT | LDAP_DEBUG_PARAMETER,
            "   url:" << url << endl);
    if (ldap_is_ldap_url(url)){
        LDAPURLDesc *urlDesc;
        ldap_url_parse(url, &urlDesc);
        if(urlDesc->lud_host){
            m_Host = string(urlDesc->lud_host);
        }
        m_Port = urlDesc->lud_port;
        if(urlDesc->lud_dn){
            m_DN = string(urlDesc->lud_dn);
        }
        m_Attrs = StringList(urlDesc->lud_attrs);
        m_Scope = urlDesc->lud_scope;
        if(urlDesc->lud_filter){
            m_Filter = string(urlDesc->lud_filter);
        }else{
            m_Filter = "";
        }
        m_urlString= string(url);
        ldap_free_urldesc(urlDesc);
    }else{
        DEBUG(LDAP_DEBUG_TRACE,"   noUrl:" << url << endl);
    }
}

LDAPUrl::~LDAPUrl(){
    DEBUG(LDAP_DEBUG_DESTROY, "LDAPUrl::~LDAPUrl()" << endl);
    m_Attrs.clear();
}

int LDAPUrl::getPort() const {
    return m_Port;
}

int LDAPUrl::getScope() const {
    return m_Scope;
}

const string& LDAPUrl::getURLString() const {
    return m_urlString;
}

const string& LDAPUrl::getHost() const {
    return m_Host;
}

const string& LDAPUrl::getDN() const {
    return m_DN;
}

const string& LDAPUrl::getFilter() const {
    return m_Filter;
}

const StringList& LDAPUrl::getAttrs() const {
    return m_Attrs;
}


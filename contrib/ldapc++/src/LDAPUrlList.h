/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_URL_LIST_H
#define LDAP_URL_LIST_H

#include <list>
#include "LDAPUrl.h"

typedef list<LDAPUrl> UrlList;

class LDAPUrlList{
    typedef UrlList::const_iterator const_iterator;

    public:
        LDAPUrlList();
        LDAPUrlList(const LDAPUrlList& urls);
        LDAPUrlList(char** urls);
        ~LDAPUrlList();

        size_t size() const;
        const_iterator begin() const;
        const_iterator end() const;

        void add(const LDAPUrl& url);

    private :
        UrlList m_urls;
};
#endif //LDAP_URL_LIST_H

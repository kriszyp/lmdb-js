/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_CONTROL_SET_H
#define LDAP_CONTROL_SET_H

#include <list>
#include <ldap.h>
#include "LDAPControl.h"

typedef list<LDAPCtrl> CtrlList;


class LDAPControlSet {
    typedef CtrlList::const_iterator const_iterator;
    public :
        LDAPControlSet();
        LDAPControlSet(const LDAPControlSet& cs);
        //!for internal use only
        //untested til now. Due to lack of server that return Controls
        LDAPControlSet(LDAPControl** controls);
        ~LDAPControlSet();
        size_t size() const ;
        const_iterator begin() const;
        const_iterator end() const;
        void add(const LDAPCtrl& ctrl); 
        
        LDAPControl** toLDAPControlArray()const ;

    private :
        CtrlList data;
} ;
#endif //LDAP_CONTROL_SET_H

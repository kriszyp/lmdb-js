/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "debug.h"

#include "LDAPAttributeList.h"

#include "LDAPException.h"
#include "LDAPAttribute.h"
#include "LDAPAsynConnection.h"
#include "LDAPMessage.h"

using namespace std;

LDAPAttributeList::LDAPAttributeList(){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttributeList::LDAPAttributList( )" << endl);
}

LDAPAttributeList::LDAPAttributeList(const LDAPAttributeList& al){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttributeList::LDAPAttributList(&)" << endl);
    m_attrs=al.m_attrs;
}

LDAPAttributeList::LDAPAttributeList(const LDAPAsynConnection *ld, 
        LDAPMessage *msg){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttributeList::LDAPAttributList()" << endl);
    BerElement *ptr=0;
    char *name=ldap_first_attribute(ld->getSessionHandle(), msg, &ptr);
/*
   This code was making problems if no attribute were returned
   How am I supposed to find decoding errors? ldap_first/next_attribute
   return 0 in case of error or if there are no more attributes. In either
   case they set the LDAP* error code to 0x54 (Decoding error) ??? Strange..

   There will be some changes in the new version of the C-API so that this
   code should work in the future.
   if(name == 0){
        ber_free(ptr,0);
        ldap_memfree(name);
        throw LDAPException(ld);
    }else{
*/        BerValue **values;
        for (;name !=0;
                name=ldap_next_attribute(ld->getSessionHandle(),msg,ptr) ){
            values=ldap_get_values_len(ld->getSessionHandle(),
                    msg, name);
            this->addAttribute(LDAPAttribute(name, values));
            ldap_memfree(name);
            ldap_value_free_len(values);
        }
        ber_free(ptr,0);
//    }
}

LDAPAttributeList::~LDAPAttributeList(){
    DEBUG(LDAP_DEBUG_DESTROY,"LDAPAttributeList::~LDAPAttributList()" << endl);
}

size_t LDAPAttributeList::size() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::size()" << endl);
    return m_attrs.size();
}

bool LDAPAttributeList::empty() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::empty()" << endl);
    return m_attrs.empty();
}

LDAPAttributeList::const_iterator LDAPAttributeList::begin() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::begin()" << endl);
    return m_attrs.begin();
}

LDAPAttributeList::const_iterator LDAPAttributeList::end() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::end()" << endl);
    return m_attrs.end();
}

void LDAPAttributeList::addAttribute(const LDAPAttribute& attr){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::addAttribute()" << endl);
    DEBUG(LDAP_DEBUG_TRACE | LDAP_DEBUG_PARAMETER,
            "   attr:" << attr << endl);
    m_attrs.push_back(attr);
}


LDAPMod** LDAPAttributeList::toLDAPModArray() const{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPAttribute::toLDAPModArray()" << endl);
    LDAPMod **ret = (LDAPMod**) malloc((m_attrs.size()+1) * sizeof(LDAPMod*));
    AttrList::const_iterator i;
    int j=0;
    for (i=m_attrs.begin(); i!= m_attrs.end(); i++, j++){
        ret[j]=i->toLDAPMod();
    }
    ret[m_attrs.size()]=0;
    return ret;
}

ostream& operator << (ostream& s, const LDAPAttributeList& al){
    AttrList::const_iterator i;
    for(i=al.m_attrs.begin(); i!=al.m_attrs.end(); i++){
        s << *i << "; ";
    }
    return s;
}


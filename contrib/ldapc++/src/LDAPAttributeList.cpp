/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAttributeList.cpp,v 1.6 2000/08/31 17:43:48 rhafer Exp $

#include "debug.h"
#include "LDAPAttributeList.h"

LDAPAttributeList::LDAPAttributeList(){
}

LDAPAttributeList::LDAPAttributeList(const LDAPAttributeList& al){
	m_attrs=al.m_attrs;
}

LDAPAttributeList::LDAPAttributeList(const LDAPAsynConnection *ld, 
        LDAPMessage *msg){
	BerElement *ptr;
	char *name;
	for	(name=ldap_first_attribute(ld->getSessionHandle(), msg, &ptr);
			name !=0;
			name=ldap_next_attribute(ld->getSessionHandle(),msg,ptr) ){
		BerValue **values=ldap_get_values_len(ld->getSessionHandle(),
                msg, name);
		this->addAttribute(LDAPAttribute(name, values));
	}
}


void LDAPAttributeList::addAttribute(const LDAPAttribute& attr){
	m_attrs.push_back(attr);
}

LDAPAttributeList::~LDAPAttributeList(){
	DEBUG(LDAP_DEBUG_TRACE,"LDAPAttributeList::~LDAPAttributList()" << endl);
}

void LDAPAttributeList::find(char *name){
}

LDAPMod** LDAPAttributeList::toLDAPModArray(){
	LDAPMod **ret = new LDAPMod*[m_attrs.size()+1];
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

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPEntry.cpp,v 1.6 2000/08/31 17:43:48 rhafer Exp $

#include "debug.h"
#include "LDAPEntry.h"

LDAPEntry::LDAPEntry(const LDAPEntry& entry){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPEntry::LDAPEntry(LDAPEntry&)" << endl);
	this->setDN(entry.m_dn);
	this->setAttributes(entry.m_attrs);
}


LDAPEntry::LDAPEntry(const char *dn, 
        LDAPAttributeList *attrs=new LDAPAttributeList()){
	m_attrs=attrs;
 	m_dn=strdup(dn);
}

LDAPEntry::LDAPEntry(const LDAPAsynConnection *ld, LDAPMessage *msg){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPEntry::LDAPEntry()" << endl);
	m_dn = ldap_get_dn(ld->getSessionHandle(),msg);
	m_attrs = new LDAPAttributeList(ld, msg);
	m_attrs->find("objectClass");
}

LDAPEntry::~LDAPEntry(){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPEntry::~LDAPEntry()" << endl);
	delete[] m_dn;
	delete m_attrs;
}

void LDAPEntry::setDN(const char* dn){
	if (m_dn != 0){
		delete[] m_dn;
	}
	m_dn=strdup(dn);
}

void LDAPEntry::setAttributes(LDAPAttributeList *attrs){
	if (m_attrs != 0){
		delete m_attrs;
	}
	m_attrs=attrs;
}

char* LDAPEntry::getDN(){
	return strdup(m_dn);
}

LDAPAttributeList* LDAPEntry::getAttributes(){
	return m_attrs;
}

ostream& operator << (ostream& s, const LDAPEntry& le){
	s << "DN: " << le.m_dn << ": " << *(le.m_attrs); 
	return s;
}

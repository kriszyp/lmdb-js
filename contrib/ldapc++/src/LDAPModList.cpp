/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPModList.cpp,v 1.3 2000/08/31 17:43:49 rhafer Exp $

#include "LDAPModList.h"

LDAPModList::LDAPModList(){
}

LDAPModList::LDAPModList(const LDAPModList&){
}

void LDAPModList::addModification(const LDAPModification &mod){
	m_modList.push_back(mod);
}

LDAPMod** LDAPModList::toLDAPModArray(){
	LDAPMod **ret = new LDAPMod*[m_modList.size()+1];
	ret[m_modList.size()]=0;
	ModList::const_iterator i;
	int j=0;
	for (i=m_modList.begin(); i != m_modList.end(); i++ , j++){
		ret[j]=i->toLDAPMod();
	}
	return ret;
}

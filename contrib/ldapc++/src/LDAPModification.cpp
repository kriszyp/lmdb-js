/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPModification.cpp,v 1.3 2000/08/31 17:43:49 rhafer Exp $

#include "LDAPModification.h"

LDAPModification::LDAPModification(const LDAPAttribute& attr, mod_op op){
	m_attr = attr;
	m_mod_op = op;
}

LDAPMod *LDAPModification::toLDAPMod() const  {
	LDAPMod* ret=m_attr.toLDAPMod();

	//The mod_op value of the LDAPMod-struct needs to be ORed with the right
	// LDAP_MOD_* constant to preserve the BIN-flag (see CAPI-draft for explanation of
	// the LDAPMod struct)
	switch (m_mod_op){
		case OP_ADD :
			ret->mod_op |= LDAP_MOD_ADD;
		break;
		case OP_DELETE :
			ret->mod_op |= LDAP_MOD_DELETE;
		break;
		case OP_REPLACE :
			ret->mod_op |= LDAP_MOD_REPLACE;
		break;
	}
	return ret;
}

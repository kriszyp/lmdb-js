/*
 * Copyright 2003, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "debug.h"
#include "StringList.h"
#include "LDAPSchema.h"

using namespace std;

LDAPSchema::LDAPSchema(){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPSchema::LDAPSchema( )" << endl);
}

LDAPSchema::~LDAPSchema() {
    DEBUG(LDAP_DEBUG_DESTROY,"LDAPSchema::~LDAPSchema()" << endl);
}

void LDAPSchema::setObjectClasses (const StringList &ocs) {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPSchema::setObjectClasses()" << endl);
    
    // parse the stringlist and save it to global map...
    StringList::const_iterator i,j;
    for (i = ocs.begin(); i != ocs.end(); i++) {
	LDAPObjClass oc ( (*i) );
	StringList names = oc.getNames();
	// there could be more names for one object...
	for (j = names.begin(); j != names.end(); j++) {
	    object_classes [(*j)] = LDAPObjClass (oc);
	}
    }
}

void LDAPSchema::setAttributeTypes (const StringList &ats) {
    DEBUG(LDAP_DEBUG_TRACE,"LDAPSchema::setAttributeTypes()" << endl);
    
    // parse the stringlist and save it to global map...
    StringList::const_iterator i,j;
    for (i = ats.begin(); i != ats.end(); i++) {
	LDAPAttrType at ( (*i) );
	StringList names = at.getNames();
	// there could be more names for one object...
	for (j = names.begin(); j != names.end(); j++) {
	    attr_types [(*j)] = LDAPAttrType (at);
	}
    }
}

LDAPObjClass LDAPSchema::getObjectClassByName (string name) {

    return object_classes [name];
}

LDAPAttrType LDAPSchema::getAttributeTypeByName (string name) {

    return attr_types [name];
}

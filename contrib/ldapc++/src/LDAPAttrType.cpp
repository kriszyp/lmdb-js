/*
 * Copyright 2003, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "debug.h"
#include "LDAPAttrType.h"


LDAPAttrType::LDAPAttrType(){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttrType::LDAPAttrType( )" << endl);

    oid = string ();
    desc = string ();
    equality = string ();
    syntax = string ();
    names = StringList ();
    single = false;
}

LDAPAttrType::LDAPAttrType (const LDAPAttrType &at){
    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttrType::LDAPAttrType( )" << endl);

    oid = at.oid;
    desc = at.desc;
    equality = at.equality;
    syntax = at.syntax;
    names = at.names;
    single = at.single;
}

LDAPAttrType::LDAPAttrType (string at_item) { 

    DEBUG(LDAP_DEBUG_CONSTRUCT,
            "LDAPAttrType::LDAPAttrType( )" << endl);

    LDAPAttributeType *a;
    int ret;
    const char *errp;
    a = ldap_str2attributetype (at_item.c_str(), &ret, &errp,SCHEMA_PARSE_FLAG);

    if (a) {
	this->setNames (a->at_names);
	this->setDesc (a->at_desc);
        this->setEquality (a->at_equality_oid);
        this->setSyntax (a->at_syntax_oid);
	this->setOid (a->at_oid);
	this->setSingle (a->at_single_value);
    }
    // else? -> error
}

LDAPAttrType::~LDAPAttrType() {
    DEBUG(LDAP_DEBUG_DESTROY,"LDAPAttrType::~LDAPAttrType()" << endl);
}

void LDAPAttrType::setSingle (int at_single) {
    single = (at_single == 1);
}
    
void LDAPAttrType::setNames (char **at_names) {
    names = StringList (at_names);
}

void LDAPAttrType::setDesc (char *at_desc) {
    desc = string ();
    if (at_desc)
	desc = at_desc;
}

void LDAPAttrType::setEquality (char *at_equality_oid) {
    equality = string ();
    if (at_equality_oid) {
	equality = at_equality_oid;
    }
}

void LDAPAttrType::setSyntax (char *at_syntax_oid) {
    syntax = string ();
    if (at_syntax_oid) {
	syntax = at_syntax_oid;
    }
}

void LDAPAttrType::setOid (char *at_oid) {
    oid = string ();
    if (at_oid)
	oid = at_oid;
}

bool LDAPAttrType::isSingle () {
    return single;
}

string LDAPAttrType::getOid () {
    return oid;
}

string LDAPAttrType::getDesc () {
    return desc;
}

string LDAPAttrType::getEquality () {
    return equality;
}

string LDAPAttrType::getSyntax () {
    return syntax;
}

StringList LDAPAttrType::getNames () {
    return names;
}

string LDAPAttrType::getName () {

    if (names.empty())
	return "";
    else
	return *(names.begin());
}

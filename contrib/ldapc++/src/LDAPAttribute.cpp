/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAttribute.cpp,v 1.3 2000/08/31 17:43:48 rhafer Exp $

//TODO!!!
//  * Spend some thoughts about binary attributes
//  * handling of subtypes (;de; and so on)
//  * For binary attributes use one of the other constructors (provided later )
//  * creatind LDAPAttributes from the CAPI-structures.
//  * Defining return values and error codes
//  * some documentation

#include <ldap.h> 
#include <ac/string.h>
#include <ctype.h>
#include "LDAPAttribute.h"


//Copy-constructor
LDAPAttribute::LDAPAttribute(const LDAPAttribute& attr){
	this->setName(attr.m_name);
	ValueList::const_iterator i;
	for (i=attr.m_values.begin(); i!=attr.m_values.end(); i++){
		this->m_values.push_back(ber_bvdup(*i));
	}
}

//This Constructor expects the parameter value to be either UTF-8 encoded
// (for LDAPv3) or T.61 encoded (for LDAPv2).
LDAPAttribute::LDAPAttribute(const char *name=0, const char *value=0){
	this->setName(name);
	this->addValue(value);
}

LDAPAttribute::LDAPAttribute(const char *name, char **values){
	this->setName(name);
	this->setValues(values);
}


LDAPAttribute::LDAPAttribute(const char *name, BerValue **values){
	this->setName(name);
	this->setValues(values);
}

LDAPAttribute::~LDAPAttribute(){
	delete[] m_name;
	ValueList::const_iterator i;
	for(i=m_values.begin(); i!=m_values.end(); i++){
		ber_bvfree(*i);
	}
	m_values.clear();
}

int LDAPAttribute::addValue(const char *value){
	if(value!=0){
		BerValue *berval=new BerValue;
		berval->bv_len=strlen(value);
		berval->bv_val=strdup(value);
		m_values.push_back(berval);
		return 0;
	}
	return -1;
}

int LDAPAttribute::addValue(const BerValue *value){
	if(value!=0){
		m_values.push_back(ber_bvdup(value));
		return 0;
	}
	return -1;
}

int LDAPAttribute::setValues(char **values){
	ValueList::const_iterator i;
	for(i=m_values.begin(); i!=m_values.end(); i++){
		delete[](*i);
	}
	m_values.clear();
	for( char **i=values; *i!=0; i++){
		this->addValue(*i);
	}
	return 0;
}

int LDAPAttribute::setValues(BerValue **values){
	ValueList::const_iterator i;
	for(i=m_values.begin(); i!=m_values.end(); i++){
		delete[](*i);
	}
	m_values.clear();
	for( BerValue **i=values; *i!=0; i++){
		this->addValue(*i);
	}
	return 0;
}
	
BerValue** LDAPAttribute::getValues() const{
	size_t size=m_values.size();
	BerValue **temp = new BerValue*[size+1];
	ValueList::const_iterator i;
	int p;

	for(i=m_values.begin(), p=0; i!=m_values.end(); i++,p++){
		temp[p]=ber_bvdup( (*i) );
	}
	temp[size]=0;
	return temp;
}

int LDAPAttribute::getNumValues() const{
	return m_values.size();
}

char* LDAPAttribute::getName(){
	return strdup(m_name);
}

int LDAPAttribute::setName(const char *name){
	if (name!=0){
		m_name=strdup(name);
	}
	return 0;
}

// The bin-FLAG of the mod_op  is always set to LDAP_MOD_BVALUES (0x80) 
LDAPMod* LDAPAttribute::toLDAPMod() const {
	LDAPMod* ret=new LDAPMod();
	ret->mod_op=LDAP_MOD_BVALUES;	//alway asume binary-Values
	ret->mod_type=strdup(m_name);
	ret->mod_bvalues=this->getValues();
	return ret;
}

bool LDAPAttribute::isNotPrintable() const {
	ValueList::const_iterator i;
	for(i=m_values.begin(); i!=m_values.end(); i++){
		ber_len_t len=(*i)->bv_len;
		for(ber_len_t j=0; j<len; j++){
			if (! isprint( (*i)->bv_val[j] ) ){
				return true;
			}
		}
	}
	return false;
}

ostream& operator << (ostream& s, const LDAPAttribute& attr){
	s << attr.m_name << "=";
	ValueList::const_iterator i;
	if (attr.isNotPrintable()){
		s << "NOT_PRINTABLE" ;
	}else{
		for(i=attr.m_values.begin(); i!=attr.m_values.end(); i++){
			s << (*i)->bv_val << " ";
		}
	}
	return s;
}

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAttribute.h,v 1.5 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_ATTRIBUTE_H
#define LDAP_ATTRIBUTE_H

#include<iostream>
#include<list>
#include<ldap.h>
#include<lber.h> 

typedef list<BerValue*> ValueList;

class LDAPAttribute{

	private :
		char *m_name;
		ValueList m_values;

	public :
		//Copy constructor
		LDAPAttribute(const LDAPAttribute& attr);
		LDAPAttribute(const char* name=0, const char *value=0);
		LDAPAttribute(const char* name, char **values);
		LDAPAttribute(const char* name, BerValue **values);
		~LDAPAttribute();

		int addValue(const char *value);
		int addValue(const BerValue *value);
		int setValues(char** values);
		int setValues(BerValue** values);
		int setValues(ValueList values);
		BerValue** getValues() const;
		int getNumValues() const;
		char* getName();
		int setName(const char *name);
		bool isNotPrintable() const ;

		LDAPMod* toLDAPMod() const ;
		
		friend ostream& operator << (ostream& s, const LDAPAttribute& attr);
};
#endif //#ifndef LDAP_ATTRIBUTE_H

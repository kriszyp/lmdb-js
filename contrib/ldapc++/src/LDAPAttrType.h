/*
 * Copyright 2003, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_ATTRTYPE_H
#define LDAP_ATTRTYPE_H

#include <ldap_schema.h>
#include <string>

#include "StringList.h"

#define SCHEMA_PARSE_FLAG    0x03


using namespace std;

/**
 * Represents the Attribute Type (from LDAP schema)
 */
class LDAPAttrType{
    private :
	StringList names;
	string desc, oid;
	bool single;
	
    public :

        /**
         * Constructor
         */   
        LDAPAttrType();

        /**
         * Copy constructor
         */   
	LDAPAttrType (const LDAPAttrType& oc);

        /**
	 * Constructs new object and fills the data structure by parsing the
	 * argument.
	 * @param at_item description of attribute type is string returned
	 *  by the search command. It is in the form:
	 * "( SuSE.YaST.Attr:19 NAME ( 'skelDir' ) DESC ''
	 *    EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"
         */   
        LDAPAttrType (string at_item);

        /**
         * Destructor
         */
        virtual ~LDAPAttrType();
	
	
	/**
	 * Returns attribute description
	 */
	string getDesc ();
	
	/**
	 * Returns attribute oid
	 */
	string getOid ();

	/**
	 * Returns attribute name (first one if there are more of them)
	 */
	string getName ();

	/**
	 * Returns all attribute names
	 */
	StringList getNames();
	
	/**
	 * Returns true if attribute type hllows only single value
	 */
	bool isSingle();
	
	void setNames (char **at_names);
	void setDesc (char *at_desc);
	void setOid (char *at_oid);
	void setSingle (int at_single_value);
	
};

#endif // LDAP_ATTRTYPE_H

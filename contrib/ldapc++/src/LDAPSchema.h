/*
 * Copyright 2003, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef LDAP_SCHEMA_H
#define LDAP_SCHEMA_H

#include <ldap.h>
#include <string>
#include <map>

#include "LDAPObjClass.h"
#include "LDAPAttrType.h"

/**
 * Represents the LDAP schema
 */
class LDAPSchema{
    private :
	/**
	 * map of object classes: index is name, value is LDAPObjClass object
	 */
	map <string, LDAPObjClass> object_classes;
	
	/**
	 * map of attribute types: index is name, value is LDAPAttrType object
	 */
	map <string, LDAPAttrType> attr_types;

    public :

        /**
         * Constructs an empty object
         */   
        LDAPSchema();

        /**
         * Destructor
         */
        virtual ~LDAPSchema();
	
        /**
         * Fill the object_classes map
	 * @param oc description of one objectclass (string returned by search
	 * command), in form:
	 * "( SuSE.YaST.OC:5 NAME 'userTemplate' SUP objectTemplate STRUCTURAL
	 *    DESC 'User object template' MUST ( cn ) MAY ( secondaryGroup ))"
         */
	void setObjectClasses (const StringList &oc);

	 /**
         * Fill the attr_types map
	 * @param at description of one attribute type
	 *  (string returned by search command), in form:
	 * "( SuSE.YaST.Attr:19 NAME ( 'skelDir' ) DESC ''
	 *    EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )"
         */
	void setAttributeTypes (const StringList &at);

	/**
	 * Returns object class object with given name
	 */
	LDAPObjClass getObjectClassByName (std::string name);
	
	/**
	 * Returns attribute type object with given name
	 */
	LDAPAttrType getAttributeTypeByName (string name);

};

#endif // LDAP_SCHEMA_H

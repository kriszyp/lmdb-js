/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_ATTRIBUTE_H
#define LDAP_ATTRIBUTE_H

#include<iostream>
#include<string>
#include<ldap.h>
#include<lber.h> 

#include "StringList.h"

//! Represents the name an value(s) of an Attribute 
class LDAPAttribute{
    public :
        //! Default constructor
        /*!
         * initializes an empty object
         */
        LDAPAttribute();

        //!Copy constructor
        /*!
         * Copies all values of an Attribute to a new one
         * @param attr   The Attribute that should be copied
         */
        LDAPAttribute(const LDAPAttribute& attr);

        //! Construct an Attribute with a single string value
        /*!
         * @param name      The attribute's name (type)
         * @param value     The string value of the attribute, if 0 the 
         *                  will have no values, for LDAPv3 this values must
         *                  be UTF-8 encoded
         */
        LDAPAttribute(const string& name, const string& value="");

        //! Construct an attribute with multiple string values
        /*!
         * @param name      The attribute's name (type)
         * @param values    A 0-terminated array of char*. Each char* specifies
         *                  one value of the attribute (UTF-8 encoded)
         */
        LDAPAttribute(const char* name, char **values);
        LDAPAttribute(const string& name, const StringList& values);
        //! Construct an attribute with multiple binary coded values
        /*!
         * @param name      The attribute's name (type)
         * @param values    0-terminated array of binary attribute values
         *                  The BerValue struct is declared as:<BR>
         *                  struct berval{
         *                      unsigned long bv_len;
         *                      char *bv_val;
         *                  } BerValue;
         */         
        LDAPAttribute(const char* name, BerValue **values);
        
        //! Destructor
        ~LDAPAttribute();

        //! Add a single string value(bin/char) to the Attribute
        /*!
         * @param value Value that should be added, it is copied inside the
         *              object
         * 
         * @return  0  no problem <BR>
         *          -1 failure (mem. allocation problem)
         */
        void addValue(const string& value);

        //! Add a single binary value to the Attribute
        /*!
         * @param value The binary coded value that should be added to the
         *              Attribute.
         * 
         * @return  0  no problem <BR>
         *          -1 failure (mem. allocation problem)
         */
        int addValue(const BerValue *value);

        /*!
         * Set the values of the attribute. If the object contains some values
         * already, they are deleted
         * @param values    0-terminated array of char*, each char* 
         *                  representing a string value to add to the entry
         * 
         * @return  0  no problem <BR>
         *          -1 failure (mem. allocation problem)
         */
        int setValues(char** values);

        /*!
         * Set the values of the attribute. If the object does already contain
         * some values, they will be deleted
         * @param values    0-terminated array of BerValue*, each BerValue
         *                  representing a binary value to add to the entry
         * 
         * @return  0  no problem <BR>
         *          -1 failure (mem. allocation problem)
         */
        int setValues(BerValue** values);
        void setValues(const StringList& values); 
        /*!
         * @return  The Values of the Attribute as an 0-terminated Array of 
         *          BerValue* (is dynamically allocated, delete it after usage) 
         *          <BR>
         *          0-pointer in case of error
         */
        BerValue** getBerValues() const;
        const StringList& getValues() const;
        /*!
         * @return The Number of values of the attribute
         */
        int getNumValues() const;

        /*!
         * @return The name(type) of the attribute
         *         <BR>
         *         0-pointer in case of error
         */
        const string& getName() const ;

        /*!
         * @param the new name of the object  
         * 
         * @return  0  no problem <BR>
         *          -1 failure (mem. allocation problem)
         */
        void setName(const string& name);

        /*!
         * for internal use only
         */
        LDAPMod* toLDAPMod() const ;

        bool isNotPrintable() const ;

    private :
        string m_name;
        StringList m_values;
        /*!
         * @return true if the values contains nonprintable characters, 
         *      otherwise false
         */

        /*!
         * just for debugging at the moment
         */
    friend ostream& operator << (ostream& s, const LDAPAttribute& attr);
};
#endif //#ifndef LDAP_ATTRIBUTE_H

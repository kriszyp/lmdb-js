/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_ATTRIBUTE_LIST_H
#define LDAP_ATTRIBUTE_LIST_H

#include <ldap.h>
#include <list>
class LDAPAttribute;
class LDAPAsynConnection;
class LDAPMsg;

typedef std::list<LDAPAttribute> AttrList;

/**
 * This container class is used to store multiple LDAPAttribute-objects.
 */
class LDAPAttributeList{
    private :
        AttrList m_attrs;

    public :
        typedef AttrList::const_iterator const_iterator;


        /**
         * Copy-constructor
         */
        LDAPAttributeList(const LDAPAttributeList& al);
        
        /**
         * For internal use only
         *
         * This constructor is used by the library internally to create a
         * list of attributes from a LDAPMessage-struct that was return by
         * the C-API
         */
        LDAPAttributeList(const LDAPAsynConnection *ld, LDAPMessage *msg);

        /**
         * Constructs an empty list.
         */   
        LDAPAttributeList();

        /**
         * Destructor
         */
        virtual ~LDAPAttributeList();

        /**
         * @return The number of LDAPAttribute-objects that are currently
         * stored in this list.
         */
        size_t size() const;

        /**
         * @return true if there are zero LDAPAttribute-objects currently
         * stored in this list.
         */
        bool empty() const;

        /**
         * @return A iterator that points to the first element of the list.
         */
        const_iterator begin() const;
        
        /**
         * @return A iterator that points to the element after the last
         * element of the list.
         */
        const_iterator end() const;

        /**
         * Adds one element to the end of the list.
         * @param attr The attribute to add to the list.
         */
        void addAttribute(const LDAPAttribute& attr);

        /**
         * Translates the list of Attributes to a 0-terminated array of
         * LDAPMod-structures as needed by the C-API
         */
        LDAPMod** toLDAPModArray() const;
        
        /**
         * This method can be used to dump the data of a LDAPResult-Object.
         * It is only useful for debugging purposes at the moment
         */
        friend std::ostream& operator << (std::ostream& s, 
					  const LDAPAttributeList& al);
};
#endif // LDAP_ATTRIBUTE_LIST_H


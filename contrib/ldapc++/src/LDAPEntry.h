/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_ENTRY_H
#define LDAP_ENTRY_H
#include <ldap.h>

#include <LDAPAsynConnection.h>
#include <LDAPAttributeList.h>

/**
 * This class is used to store every kind of LDAP Entry.
 */
class LDAPEntry{

	public :
        /**
         * Copy-constructor
         */
		LDAPEntry(const LDAPEntry& entry);

        /**
         * Constructs a new entry (also used as standard constructor).
         *
         * @param dn    The Distinguished Name for the new entry.
         * @param attrs The attributes for the new entry.
         */
		LDAPEntry(const std::string& dn=std::string(), 
                const LDAPAttributeList *attrs=new LDAPAttributeList());

        /**
         * Used internally only.
         *
         * The constructor is used internally to create a LDAPEntry from
         * the C-API's data structurs.
         */ 
		LDAPEntry(const LDAPAsynConnection *ld, LDAPMessage *msg);

        /**
         * Destructor
         */
		~LDAPEntry();
        
        /**
         * Sets the DN-attribute.
         * @param dn: The new DN for the entry.
         */
		void setDN(const std::string& dn);

        /**
         * Sets the attributes of the entry.
         * @param attr: A pointer to a std::list of the new attributes.
         */
		void setAttributes(LDAPAttributeList *attrs);

        /**
         * @returns The current DN of the entry.
         */
		const std::string& getDN() const ;

        /**
         * @returns A const pointer to the attributes of the entry.  
         */
		const LDAPAttributeList* getAttributes() const;

        /**
         * This method can be used to dump the data of a LDAPResult-Object.
         * It is only useful for debugging purposes at the moment
         */
		friend std::ostream& operator << (std::ostream& s, const LDAPEntry& le);
	
    private :

		LDAPAttributeList *m_attrs;
		std::string m_dn;
};
#endif  //LDAP_ENTRY_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPAsynConnection.h,v 1.4 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_ASYN_CONNECTION_H
#define LDAP_ASYN_CONNECTION_H

#include<iostream.h>
#include<ldap.h>
#include<lber.h>

#include "LDAPMessageQueue.h"
#include "LDAPConstraints.h"
#include "LDAPModification.h"
#include "LDAPModList.h"
#include "LDAPUrl.h"
#include "LDAPUrlList.h"

class LDAPEntry;
class LDAPAttribute;

//! Main class for an asynchronous LDAP connection 
/*!
 * This class represents an asynchronous connection to an LDAP-Server. It 
 * provides the methods for authentication, and all other LDAP-Operations
 * (e.g. search, add, delete, etc.)
 * All of the LDAP-Operations return a pointer to a LDAPMessageQueue-Object,
 * which can be used to obtain the results of that operation.
 * A basic example of this class could be like this:  <BR>
 * 1. Create a new LDAPAsynConnection Object: <BR>
 * 2. Use the init-method to initialize the connection <BR>
 * 3. Call the bind-method to authenticate to the directory <BR>
 * 4. Obtain the bind results from the return LDAPMessageQueue-Object <BR>
 * 5. Perform on of the operations on the directory (add, delete, search, ..)
 *    <BR>
 * 6. Use the return LDAPMessageQueue to obtain the results of the operation 
 * <BR>
 * 7. Close the connection (feature not implemented yet :) ) <BR>
 */
class LDAPAsynConnection{

    private :
        LDAP *cur_session;
        LDAPConstraints *m_constr;
    public :
        static const int SEARCH_BASE=0;
        static const int SEARCH_ONE=1;
        static const int SEARCH_SUB=2;

        //! Construtor that initializes a connection to a server
        /*!
         * @param hostname Name (or IP-Adress) of the destination host
         * @param port Port the LDAP server is running on
         * @param cons Default constraints to use with operations over 
         *      this connection
         */
        LDAPAsynConnection(const char* hostname="localhost", int port=389, 
                LDAPConstraints *cons=new LDAPConstraints() );

        //! Change the default constraints of the connection
        /*!
         * @cons cons New LDAPConstraints to use with the connection
         */
        void setConstraints(LDAPConstraints *cons);
        
        //! Get the default constraints of the connection
        /*!
         * @return Pointer to the LDAPConstraints-Object that is currently
         *      used with the Connection
         */
        LDAPConstraints* getConstraints() const;

        //! used internally only for automatic referral chasing
        LDAPAsynConnection* referralConnect(const LDAPUrlList *urls,
                LDAPUrl** usedUrl) const;

        /*! 
         * Initzializes a connection to a server. There actually no
         * communication to the server. Just the object is initialized
         * (e.g. this method is called with the 
         * LDAPAsynConnection(char*,int,LDAPConstraints) constructor.)
         */
        void init(const char* hostname, int port);

        //! Simple authentication to a LDAP-Server
        /*!
         * This method does a simple (username, password) bind to the server.
         * Other, saver, authentcation methods are provided later
         * @param dn the distiguished name to bind as
         * @param passwd cleartext password to use
         */
        LDAPMessageQueue* bind(const char* dn, const char *passwd,
                const LDAPConstraints *cons=0);

        //! Performing a search on a directory tree.
        /*!
         * Use the search method to perform a search on the LDAP-Directory
         * @param base The distinguished name of the starting point for the
         *      search operation
         * @param scope The scope of the search. Possible values: <BR> 
         *      LDAPAsynConnection::SEARCH_BASE, <BR> 
         *      LDAPAsynConnection::SEARCH_ONE, <BR>
         *      LDAPAsynConnection::SEARCH_SUB
         * @param cons A set of constraints that should be used with this
         *      request
         */
        LDAPMessageQueue* search(const char *base, int scope=0, 
                                 const char *filter=0, char **attrs=0, 
                                 const LDAPConstraints *cons=0);
        
        //! Delete an entry from the directory
        /*!
         * This method sends a delete request to the server
         * @param dn    Distinguished name of the entry that should be deleted
         * @param cons  A set of constraints that should be used with this
         *              request
         */
        LDAPMessageQueue* del(const char *dn, const LDAPConstraints *cons=0);
        
        //! Perform the compare operation on an attribute 
        /*!
         * @param dn    Distinguished name of the entry for which the compare
         *              should be performed
         * @param attr  An Attribute (one (!) value) to use for the
         *      compare operation
         * @param cons  A set of constraints that should be used with this
         *              request
         */
        LDAPMessageQueue* compare(const char *dn, const LDAPAttribute *attr, 
                const LDAPConstraints *cons);

        //! Add an entry to the directory
        /*!
         * @see LDAPEntry
         * @param le The entry that will be added to the directory
         */
        LDAPMessageQueue* add(LDAPEntry *le, const LDAPConstraints *const=0);

        //! Apply one modification to an attribute of a datebase entry
        LDAPMessageQueue* modify(char *dn, LDAPModification *mod);

        //! Apply multiple modifications to attrbutes of an entry
        LDAPMessageQueue* modify(const char *dn, LDAPModList *modlist,
                const LDAPConstraints *cons);

        LDAPMessageQueue* rename(const char *dn, const char *newRDN,
                bool delOldRDN, const char *newParentDN,
                const LDAPConstraints *cons);
        
        LDAPMessageQueue* extOperation(const char* oid, BerValue* value,
                const LDAPConstraints *cons);
        
        void abandon(LDAPMessageQueue *q);

        LDAP* getSessionHandle() const ;
};
#endif //LDAP_CONNECTION_H



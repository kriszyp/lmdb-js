/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#ifndef LDAP_EXCEPTION_H
#define LDAP_EXCEPTION_H

#include <iostream>
#include <string>

class LDAPAsynConnection;

/**
 * This class is only thrown as an Exception and used to signalize error
 * conditions during LDAP-operations
 */
class LDAPException{
		
	public :
        /**
         * Constructs a LDAPException-object from the parameters
         * @param res_code A valid LDAP result code.
         * @param err_string    An addional error message for the error
         *                      that happend (optional)
         */
		LDAPException(int res_code, const string& err_string=string());
		
        /**
         * Constructs a LDAPException-object from the error state of a
         * LDAPAsynConnection-object
         * @param lc A LDAP-Connection for that an error has happend. The
         *          Constructor tries to read its error state.
         */
        LDAPException(const LDAPAsynConnection *lc);

        /**
         * Destructor
         */
        virtual ~LDAPException();

        /**
         * @return The Result code of the object
         */
        
		int getResultCode() const;

        /**
         * @return The error message that is corresponding to the result
         *          code .
         */
		const string& getResultMsg() const;
        
        /**
         * @return The addional error message of the error (if it was set)
         */
        const string& getServerMsg() const;

        /**
         * This method can be used to dump the data of a LDAPResult-Object.
         * It is only useful for debugging purposes at the moment
         */
		friend ostream& operator << (ostream &s, LDAPException e);

	private :
		int m_res_code;
		string m_res_string;
		string m_err_string;
};
#endif //LDAP_EXCEPTION_H

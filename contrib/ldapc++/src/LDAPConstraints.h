/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPConstraints.h,v 1.10 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_CONSTRAINTS_H
#define LDAP_CONSTRAINTS_H 
#include <list>
#include "config.h"
#include "ac/time.h"

#include "LDAPControl.h"
#include <ldap.h>


//TODO!!
// * implement the Alias-Handling Option (OPT_DEREF)
// * the Restart-Option ???
// * default Server(s)

typedef list<LDAPCtrl*> LDAPControlSet;
//! Class for representating the various protocol options
/*! This class represents some options that can be set for a LDAPConnection
 *  operation. Namely these are time and size limits. Options for referral
 *  chasing and a default set of client of server controls to be used with
 *  every request
 */
class LDAPConstraints{
	
	private :
        //! max. time the server may spend for a search request
		int m_maxTime;

		//! max number of entries to be return from a search request
		int m_maxSize;
		
		//! Flag for enabling automatic referral/reference chasing
		bool m_referralChase;

        //! Alias dereferencing option
        int m_deref;
		
		//! List of Client Controls that should be used for each request	
		LDAPControlSet m_clientControls;

		//! List of Server Controls that should be used for each request	
		LDAPControlSet m_serverControls;

	public :
		//! Constructs a LDAPConstraints object with default values
		LDAPConstraints();

		//! Copy constructor
		LDAPConstraints(const LDAPConstraints& c);

        ~LDAPConstraints();
		
		void setMaxTime(int t);
		void setSizeLimit(int s);
		void setReferralChase(bool rc);
		int getMaxTime() const ;
		int getSizeLimit() const;
        LDAPControl** getSrvCtrlsArray() const;
        LDAPControl** getClCtrlsArray() const;
        timeval* getTimeoutStruct() const;
		bool getReferralChase() const ;
};
#endif //LDAP_CONSTRAINTS_H

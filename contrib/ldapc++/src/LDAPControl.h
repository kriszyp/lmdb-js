/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

// $Id: LDAPControl.h,v 1.4 2000/08/31 17:43:48 rhafer Exp $

#ifndef LDAP_CONTROL_H
#define LDAP_CONTROL_H

#include <lber.h>

class LDAPCtrl{
	private :
		char *m_oid;
		BerValue *m_data;
		bool m_isCritical;

	public :
		LDAPCtrl(char *oid, bool critical,  char *value=0, int length=0);
		
};

#endif //LDAP_CONTROL_H

/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef DEBUG_H
#define DEBUG_H
#include <iostream>

#define LDAP_DEBUG_NONE         0x0000
#define LDAP_DEBUG_TRACE        0x0001
#define LDAP_DEBUG_CONSTRUCT    0x0002
#define LDAP_DEBUG_DESTROY      0x0004
#define LDAP_DEBUG_PARAMETER    0x0008
#define LDAP_DEBUG_ANY -1

#define DEBUGLEVEL LDAP_DEBUG_ANY

#define PRINT_FILE	\
	cerr << "file: " __FILE__  << " line: " << __LINE__ 

#define DEBUG(level, arg)       \
    if((level) & DEBUGLEVEL){     \
        cerr  << arg ;          \
    } 

/*
*	#undef DEBUG
*	#define DEBUG(level,arg)
*/

#endif // DEBUG_H

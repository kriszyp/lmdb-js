/* operational.c - bdb backend operational attributes function */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb.h"
#include "proto-bdb.h"

/*
 * sets *hasSubordinates to LDAP_COMPARE_TRUE/LDAP_COMPARE_FALSE
 * if the entry has children or not.
 */
int
bdb_hasSubordinates(
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	int		*hasSubordinates )
{
	int		rc;
	
	assert( e );
	assert( hasSubordinates );

retry:
	rc = bdb_dn2id_children( be, NULL, &e->e_nname, 0 );
	
	switch( rc ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		ldap_pvt_thread_yield();
		goto retry;

	case 0:
		*hasSubordinates = LDAP_COMPARE_TRUE;
		break;

	case DB_NOTFOUND:
		*hasSubordinates = LDAP_COMPARE_FALSE;
		rc = LDAP_SUCCESS;
		break;

	default:
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"=> bdb_hasSubordinates: has_children failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#else
		Debug(LDAP_DEBUG_ARGS, 
			"<=- bdb_hasSubordinates: has_children failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#endif
		rc = LDAP_OTHER;
	}

	return rc;
}

/*
 * sets the supported operational attributes (if required)
 */
int
bdb_operational(
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	AttributeName		*attrs,
	int		opattrs,
	Attribute	**a )
{
	Attribute	**aa = a;
	int		rc = 0;
	
	assert( e );

	if ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) {
		int	hasSubordinates;

		rc = bdb_hasSubordinates( be, conn, op, e, &hasSubordinates );
		if ( rc == LDAP_SUCCESS ) {
			*aa = slap_operational_hasSubordinate( hasSubordinates == LDAP_COMPARE_TRUE );
			if ( *aa != NULL ) {
				aa = &(*aa)->a_next;
			}
		}
	}

	return rc;
}


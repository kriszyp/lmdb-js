/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>

#include "slap.h"
#include "proto-sql.h"

/*
 * sets the supported operational attributes (if required)
 */

int
backsql_operational(
	Operation	*op,
	SlapReply	*rs,
	int		opattrs,
	Attribute	**a )
{

	backsql_info 		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh = SQL_NULL_HDBC;
	Attribute		**aa = a;
	int			rc = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_operational(): entry \"%s\"\n",
			rs->sr_entry->e_nname.bv_val, 0, 0 );


	if ( ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates, rs->sr_attrs ) ) 
			&& attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_hasSubordinates ) == NULL ) {
		
		rc = backsql_get_db_conn( op, &dbh );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_operational(): "
				"could not get connection handle - exiting\n", 
				0, 0, 0 );
			return 1;
		}
		
		rc = backsql_has_children( bi, dbh, &rs->sr_entry->e_nname );

		switch( rc ) {
		case LDAP_COMPARE_TRUE:
		case LDAP_COMPARE_FALSE:
			*aa = slap_operational_hasSubordinate( rc == LDAP_COMPARE_TRUE );
			if ( *aa != NULL ) {
				aa = &(*aa)->a_next;
			}
			rc = 0;
			break;

		default:
			Debug( LDAP_DEBUG_TRACE, "backsql_operational(): "
				"has_children failed( %d)\n", rc, 0, 0 );
			rc = 1;
			break;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_operational()\n", 0, 0, 0);

	return rc;
}

#endif /* SLAPD_SQL */


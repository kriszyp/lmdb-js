/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "entry-id.h"

int
backsql_compare(
	BackendDB	*bd,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn,
	AttributeAssertion *ava )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_compare() - not implemented\n",
			0, 0, 0 );
	return 1;
}

int
backsql_abandon(
	BackendDB 	*be,
	Connection	*conn, 
	Operation	*op, 
	int		msgid )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_abandon()\n", 0, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_abandon()\n", 0, 0, 0 );
	return 0;
}


/*
 * sets the supported operational attributes (if required)
 */

int
backsql_operational(
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	AttributeName	*attrs,
	int		opattrs,
	Attribute	**a )
{

	backsql_info 		*bi = (backsql_info*)be->be_private;
	SQLHDBC 		dbh = SQL_NULL_HDBC;
	Attribute		**aa = a;
	int			rc = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_operational(): entry '%s'\n",
			e->e_nname.bv_val, 0, 0 );


	if ( ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) 
			&& attr_find( e->e_attrs, slap_schema.si_ad_hasSubordinates ) == NULL ) {
		
		rc = backsql_get_db_conn( be, conn, &dbh );
		if ( rc != LDAP_SUCCESS ) {
			goto no_connection;
		}
		
		rc = backsql_has_children( bi, dbh, &e->e_nname );

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
			Debug(LDAP_DEBUG_TRACE, 
				"backsql_operational(): "
				"has_children failed( %d)\n", 
				rc, 0, 0 );
			rc = 1;
			break;
		}
	}

	return rc;

no_connection:;
	Debug( LDAP_DEBUG_TRACE, "backsql_operational(): "
		"could not get connection handle - exiting\n", 
		0, 0, 0 );
	send_ldap_result( conn, op, rc, "", 
			rc == LDAP_OTHER ? "SQL-backend error" : "",
			NULL, NULL );
	return 1;
}

#endif /* SLAPD_SQL */


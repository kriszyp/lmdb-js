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
#include <string.h>
#include <sys/types.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"

int
backsql_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv )
{
	backsql_info 	*si = (backsql_info *)be->be_private;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_config()\n", 0, 0, 0 );
	assert( si );
  
	if ( !strcasecmp( argv[ 0 ], "dbhost" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing hostname in dbhost directive\n",
				fname, lineno, 0 );
			return 1;
	    	}
		si->dbhost = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE,
			"<==backsql_db_config(): hostname=%s\n",
			si->dbhost, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "dbuser" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing username in dbuser directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->dbuser = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): dbuser=%s\n",
			si->dbuser, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "dbpasswd" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing password in dbpasswd directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->dbpasswd = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"dbpasswd=%s\n", /* si->dbpasswd */ "xxxx", 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "dbname" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing database name in dbname directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->dbname = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): dbname=%s\n",
			si->dbname, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "subtree_cond" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL condition "
				"in subtree_cond directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->subtree_cond = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"subtree_cond=%s\n", si->subtree_cond, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "oc_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in oc_query directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->oc_query = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"oc_query=%s\n", si->oc_query, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "at_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in at_query directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->at_query = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"at_query=%s\n", si->at_query, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "insentry_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in insentry_query directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->insentry_query = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"insentry_query=%s\n", si->insentry_query, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "upper_func" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing function name "
				"in upper_func directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->upper_func = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"upper_func=%s\n", si->upper_func, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "strcast_func" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing function name "
				"in strcast_func directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->strcast_func = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"strcast_func=%s\n", si->strcast_func, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "delentry_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in delentry_query directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->delentry_query = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"delentry_query=%s\n", si->delentry_query, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "has_ldapinfo_dn_ru") ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing { yes | no }"
				"in has_ldapinfo_dn_ru directive\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			si->has_ldapinfo_dn_ru = 1;
		} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			si->has_ldapinfo_dn_ru = 0;
		} else {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"has_ldapinfo_dn_ru directive arg "
				"must be \"yes\" or \"no\"\n",
				fname, lineno, 0 );
			return 1;

		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"has_ldapinfo_dn_ru=%s\n", 
			si->has_ldapinfo_dn_ru == 0 ? "no" : "yes", 0, 0 );

	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config (%s line %d): "
			"unknown directive '%s' (ignored)\n",
			fname, lineno, argv[ 0 ] );
	}

	return 0;
}

#endif /* SLAPD_SQL */


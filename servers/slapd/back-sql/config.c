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
#include "ac/string.h"
#include <sys/types.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "util.h"

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
				"missing hostname in \"dbhost\" directive\n",
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
				"missing username in \"dbuser\" directive\n",
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
				"missing password in \"dbpasswd\" directive\n",
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
				"missing database name in \"dbname\" "
				"directive\n", fname, lineno, 0 );
			return 1;
		}
		si->dbname = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): dbname=%s\n",
			si->dbname, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "concat_pattern" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing pattern"
				"in \"concat_pattern\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		if ( backsql_split_pattern( argv[ 1 ], &si->concat_func, 2 ) ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"unable to parse pattern \"%s\"\n"
				"in \"concat_pattern\" directive\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"concat_pattern=\"%s\"\n", argv[ 1 ], 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "subtree_cond" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL condition "
				"in \"subtree_cond\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0, 1, &si->subtree_cond );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"subtree_cond=%s\n", si->subtree_cond.bv_val, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "children_cond" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL condition "
				"in \"children_cond\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0, 1, &si->children_cond );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"subtree_cond=%s\n", si->children_cond.bv_val, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "oc_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE, 
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in \"oc_query\" directive\n",
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
				"in \"at_query\" directive\n",
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
				"in \"insentry_query\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		si->insentry_query = ch_strdup( argv[ 1 ] );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"insentry_query=%s\n", si->insentry_query, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "create_needs_select" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing { yes | no }"
				"in \"create_needs_select\" directive\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			si->bsql_flags |= BSQLF_CREATE_NEEDS_SELECT;

		} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			si->bsql_flags &= ~BSQLF_CREATE_NEEDS_SELECT;

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"\"create_needs_select\" directive arg "
				"must be \"yes\" or \"no\"\n",
				fname, lineno, 0 );
			return 1;

		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"create_needs_select =%s\n", 
			BACKSQL_CREATE_NEEDS_SELECT( si ) ? "yes" : "no",
			0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "upper_func" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing function name "
				"in \"upper_func\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0, 1, &si->upper_func );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"upper_func=%s\n", si->upper_func.bv_val, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "upper_needs_cast" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing { yes | no }"
				"in \"upper_needs_cast\" directive\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			si->bsql_flags |= BSQLF_UPPER_NEEDS_CAST;

		} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			si->bsql_flags &= ~BSQLF_UPPER_NEEDS_CAST;

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"\"upper_needs_cast\" directive arg "
				"must be \"yes\" or \"no\"\n",
				fname, lineno, 0 );
			return 1;

		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"upper_needs_cast =%s\n", 
			BACKSQL_UPPER_NEEDS_CAST( si ) ? "yes" : "no", 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "strcast_func" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing function name "
				"in \"strcast_func\" directive\n",
				fname, lineno, 0 );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0, 1, &si->strcast_func );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"strcast_func=%s\n", si->strcast_func.bv_val, 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "delentry_query" ) ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing SQL statement "
				"in \"delentry_query\" directive\n",
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
				"in \"has_ldapinfo_dn_ru\" directive\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			si->bsql_flags |= BSQLF_HAS_LDAPINFO_DN_RU;
			si->bsql_flags |= BSQLF_DONTCHECK_LDAPINFO_DN_RU;

		} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			si->bsql_flags &= ~BSQLF_HAS_LDAPINFO_DN_RU;
			si->bsql_flags |= BSQLF_DONTCHECK_LDAPINFO_DN_RU;

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"\"has_ldapinfo_dn_ru\" directive arg "
				"must be \"yes\" or \"no\"\n",
				fname, lineno, 0 );
			return 1;

		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"has_ldapinfo_dn_ru=%s\n", 
			BACKSQL_HAS_LDAPINFO_DN_RU( si ) ? "yes" : "no", 0, 0 );

	} else if ( !strcasecmp( argv[ 0 ], "fail_if_no_mapping") ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"missing { yes | no }"
				"in \"fail_if_no_mapping\" directive\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			si->bsql_flags |= BSQLF_FAIL_IF_NO_MAPPING;

		} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			si->bsql_flags &= ~BSQLF_FAIL_IF_NO_MAPPING;

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"<==backsql_db_config (%s line %d): "
				"\"fail_if_no_mapping\" directive arg "
				"must be \"yes\" or \"no\"\n",
				fname, lineno, 0 );
			return 1;

		}
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config(): "
			"fail_if_no_mapping=%s\n", 
			BACKSQL_FAIL_IF_NO_MAPPING( si ) ? "yes" : "no", 0, 0 );

	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_db_config (%s line %d): "
			"unknown directive \"%s\" (ignored)\n",
			fname, lineno, argv[ 0 ] );
	}

	return 0;
}

#endif /* SLAPD_SQL */


/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */
/*
 *	 Copyright 2002, Pierangelo Masarati <ando@OpenLDAP.org>.
 *	 All rights reserved.
 *
 *	 This is a modified version of back-sql; the same conditions
 *	 of the above reported Copyright statement, and sigificantly
 *	 the OpenLDAP Public License apply.  Credits go to Dmitry 
 *	 Kovalev for the initial development of the backend.
 *
 *	 This copyright statement cannot be altered.
 */
/*
 *	 The following changes have been addressed:
 *	 
 * Enhancements:
 *   - re-styled code for better readability
 *   - upgraded backend API to reflect recent changes
 *   - LDAP schema is checked when loading SQL/LDAP mapping
 *   - AttributeDescription/ObjectClass pointers used for more efficient
 *     mapping lookup
 *   - bervals used where string length is required often
 *   - atomized write operations by committing at the end of each operation
 *     and defaulting connection closure to rollback
 *   - added LDAP access control to write operations
 *   - fully implemented modrdn (with rdn attrs change, deleteoldrdn,
 *     access check, parent/children check and more)
 *   - added parent access control, children control to delete operation
 *   - added structuralObjectClass operational attribute check and
 *     value return on search
 *   - added hasSubordinate operational attribute on demand
 *   - search limits are appropriately enforced
 *   - function backsql_strcat() has been made more efficient
 *   - concat function has been made configurable by means of a pattern
 *   - added config switches:
 *       - fail_if_no_mapping	write operations fail if there is no mapping
 *       - has_ldapinfo_dn_ru	overrides autodetect
 *       - concat_pattern	a string containing two '?' is used
 * 				(note that "?||?" should be more portable
 * 				than builtin function "CONCAT(?,?)")
 *       - strcast_func		cast of string constants in "SELECT DISTINCT
 *				statements (needed by PostgreSQL)
 *       - upper_needs_cast	cast the argument of upper when required
 * 				(basically when building dn substring queries)
 *   - added noop control
 *   - added values return filter control
 *   - hasSubordinate can be used in search filters (with limitations)
 *   - eliminated oc->name; use oc->oc->soc_cname instead
 * 
 * Todo:
 *   - add security checks for SQL statements that can be injected (?)
 *   - re-test with previously supported RDBMs
 *   - replace dn_ru and so with normalized dn (no need for upper() and so
 *     in dn match)
 *   - implement a backsql_normalize() function to replace the upper()
 *     conversion routines
 *   - note that subtree deletion, subtree renaming and so could be easily
 *     implemented (rollback and consistency checks are available :)
 *   - implement "lastmod" and other operational stuff (ldap_entries table ?)
 *   - check how to allow multiple operations with one statement, to remove
 *     BACKSQL_REALLOC_STMT from modify.c (a more recent unixODBC lib?)
 */

#ifndef __BACKSQL_H__
#define __BACKSQL_H__

#include "external.h"
#include "sql-types.h"

/*
 * Better use the standard length of 8192 (as of servers/slapd/dn.c) ?
 */
#define BACKSQL_MAX_DN_LEN	255

/*
 * define to enable very extensive trace logging (debug only)
 */
#undef BACKSQL_TRACE

typedef struct {
	char		*dbhost;
	int		dbport;
	char		*dbuser;
	char		*dbpasswd;
	char		*dbname;
 	/*
	 * SQL condition for subtree searches differs in syntax:
	 * "LIKE CONCAT('%',?)" or "LIKE '%'+?" or "LIKE '%'||?"
	 * or smth else 
	 */
	struct berval	subtree_cond;
	struct berval	children_cond;
	char		*oc_query, *at_query;
	char		*insentry_query,*delentry_query;
	char		*id_query;
	char		*has_children_query;
	struct berval	upper_func;
	struct berval	upper_func_open;
	struct berval	upper_func_close;
	BerVarray	concat_func;

	unsigned int	bsql_flags;
#define	BSQLF_SCHEMA_LOADED		0x0001
#define	BSQLF_UPPER_NEEDS_CAST		0x0002
#define	BSQLF_CREATE_NEEDS_SELECT	0x0004
#define	BSQLF_FAIL_IF_NO_MAPPING	0x0008
#define BSQLF_HAS_LDAPINFO_DN_RU	0x0010
#define BSQLF_DONTCHECK_LDAPINFO_DN_RU	0x0020
#define BSQLF_USE_REVERSE_DN		0x0040

#define	BACKSQL_SCHEMA_LOADED(si) \
	((si)->bsql_flags & BSQLF_SCHEMA_LOADED)
#define BACKSQL_UPPER_NEEDS_CAST(si) \
	((si)->bsql_flags & BSQLF_UPPER_NEEDS_CAST)
#define BACKSQL_CREATE_NEEDS_SELECT(si) \
	((si)->bsql_flags & BSQLF_CREATE_NEEDS_SELECT)
#define BACKSQL_FAIL_IF_NO_MAPPING(si) \
	((si)->bsql_flags & BSQLF_FAIL_IF_NO_MAPPING)
#define BACKSQL_HAS_LDAPINFO_DN_RU(si) \
	((si)->bsql_flags & BSQLF_HAS_LDAPINFO_DN_RU)
#define BACKSQL_DONTCHECK_LDAPINFO_DN_RU(si) \
	((si)->bsql_flags & BSQLF_DONTCHECK_LDAPINFO_DN_RU)
#define BACKSQL_USE_REVERSE_DN(si) \
	((si)->bsql_flags & BSQLF_USE_REVERSE_DN)
	
	struct berval	strcast_func;
	Avlnode		*db_conns;
	Avlnode		*oc_by_oc;
	Avlnode		*oc_by_id;
	ldap_pvt_thread_mutex_t		dbconn_mutex;
	ldap_pvt_thread_mutex_t		schema_mutex;
 	SQLHENV		db_env;
} backsql_info;

#define BACKSQL_SUCCESS( rc ) \
	( (rc) == SQL_SUCCESS || (rc) == SQL_SUCCESS_WITH_INFO )

#endif /* __BACKSQL_H__ */


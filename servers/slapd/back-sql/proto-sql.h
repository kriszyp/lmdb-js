/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
 * Portions Copyright 2002 Pierangelo Mararati.
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
 * by OpenLDAP Software.  Additional significant contributors include
 *    Pierangelo Mararati
 */

/*
 * The following changes have been addressed:
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

#ifndef PROTO_SQL_H
#define PROTO_SQL_H

#include "back-sql.h"
#include "sql-types.h"

/*
 * add.c
 */
int backsql_modify_delete_all_values(
	Operation 		*op,
	SlapReply		*rs,
	SQLHDBC			dbh, 
	backsql_entryID		*e_id,
	backsql_at_map_rec	*at );

int backsql_modify_internal(
	Operation 		*op,
	SlapReply		*rs,
	SQLHDBC			dbh, 
	backsql_oc_map_rec	*oc,
	backsql_entryID		*e_id,
	Modifications		*modlist );

/*
 * api.c
 */
int backsql_api_config( backsql_info *si, const char *name );
int backsql_api_register( backsql_api *ba );
int backsql_api_dn2odbc( Operation *op, SlapReply *rs, struct berval *dn );
int backsql_api_odbc2dn( Operation *op, SlapReply *rs, struct berval *dn );

/*
 * entry-id.c
 */

/* stores in *id the ID in table ldap_entries corresponding to DN, if any */
int backsql_dn2id( backsql_info *bi, backsql_entryID *id,
		SQLHDBC dbh, struct berval *dn );

/* stores in *nchildren the count of children for an entry */
int backsql_count_children( backsql_info *bi, SQLHDBC dbh,
		struct berval *dn, unsigned long *nchildren );

/* returns LDAP_COMPARE_TRUE/LDAP_COMPARE_FALSE if the entry corresponding
 * to DN has/has not children */
int backsql_has_children( backsql_info *bi, SQLHDBC dbh, struct berval *dn );

/* frees *id and returns next in list */
backsql_entryID *backsql_free_entryID( backsql_entryID *id, int freeit );

/* turns an ID into an entry */
int backsql_id2entry( backsql_srch_info *bsi, backsql_entryID *id );

/*
 * schema-map.c
 */

int backsql_load_schema_map( backsql_info *si, SQLHDBC dbh );

backsql_oc_map_rec *backsql_oc2oc( backsql_info *si, ObjectClass *oc );

backsql_oc_map_rec *backsql_id2oc( backsql_info *si, unsigned long id );

backsql_oc_map_rec * backsql_name2oc( backsql_info *si,
		struct berval *oc_name );

backsql_at_map_rec *backsql_ad2at( backsql_oc_map_rec *objclass,
		AttributeDescription *ad );

int backsql_supad2at( backsql_oc_map_rec *objclass,
		AttributeDescription *supad, backsql_at_map_rec ***pret );

int backsql_destroy_schema_map( backsql_info *si );

/*
 * search.c
 */

void backsql_init_search( backsql_srch_info *bsi, 
		struct berval *nbase, int scope, int slimit, int tlimit,
		time_t stoptime, Filter *filter, SQLHDBC dbh,
		Operation *op, SlapReply *rs, AttributeName *attrs );

/*
 * sql-wrap.h
 */

RETCODE backsql_Prepare( SQLHDBC dbh, SQLHSTMT *sth, char* query, int timeout );

#define backsql_BindParamStr( sth, par_ind, str, maxlen ) 		\
	SQLBindParameter( (sth), (SQLUSMALLINT)(par_ind), 		\
			SQL_PARAM_INPUT,				\
			SQL_C_CHAR, SQL_VARCHAR,			\
         		(SQLUINTEGER)(maxlen), 0, (SQLPOINTER)(str),	\
			(SQLUINTEGER)(maxlen), NULL )

#define backsql_BindParamID( sth, par_ind, id )				\
	SQLBindParameter( (sth), (SQLUSMALLINT)(par_ind),		\
			SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,	\
			0, 0, (SQLPOINTER)(id), 0, (SQLINTEGER*)NULL )

RETCODE backsql_BindRowAsStrings( SQLHSTMT sth, BACKSQL_ROW_NTS *row );

RETCODE backsql_FreeRow( BACKSQL_ROW_NTS *row );

void backsql_PrintErrors( SQLHENV henv, SQLHDBC hdbc, SQLHSTMT sth, int rc );

int backsql_init_db_env( backsql_info *si );

int backsql_free_db_env( backsql_info *si );

int backsql_get_db_conn( Operation *op, SQLHDBC *dbh );

int backsql_free_db_conn( Operation *op );

/*
 * util.c
 */

extern char 
	backsql_def_oc_query[],
	backsql_def_needs_select_oc_query[],
	backsql_def_at_query[],
	backsql_def_delentry_query[],
	backsql_def_insentry_query[],
	backsql_def_delobjclasses_query[],
	backsql_def_delreferrals_query[],
	backsql_def_subtree_cond[],
	backsql_def_upper_subtree_cond[],
	backsql_id_query[],
	backsql_def_concat_func[];
extern char 
	backsql_check_dn_ru_query[];

struct berbuf * backsql_strcat( struct berbuf *dest, ... );
struct berbuf * backsql_strfcat( struct berbuf *dest, const char *fmt, ... );

int backsql_entry_addattr( Entry *e, struct berval *at_name, 
		struct berval *at_val, void *memctx );

int backsql_merge_from_clause( struct berbuf *dest_from, 
		struct berval *src_from );

int backsql_split_pattern( const char *pattern, BerVarray *split_pattern,
		int expected );

int backsql_prepare_pattern( BerVarray split_pattern, BerVarray values,
		struct berval *res );

#endif /* PROTO_SQL_H */

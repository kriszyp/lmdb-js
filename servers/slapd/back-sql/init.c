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
#include "ldap_pvt.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "util.h"

#ifdef SLAPD_SQL_DYNAMIC

int
backsql_LTX_init_module(
	int 		argc, 
	char 		*argv[] )
{
	BackendInfo bi;

	memset( &bi, '\0', sizeof( bi ) );
	bi.bi_type = "sql";
	bi.bi_init = sql_back_initialize;

	backend_add( &bi );
	return 0;
}

#endif /* SLAPD_SHELL_DYNAMIC */

int
sql_back_initialize(
	BackendInfo	*bi )
{ 
	static char *controls[] = {
#ifdef LDAP_CONTROL_NOOP
		LDAP_CONTROL_NOOP,
#endif
#ifdef LDAP_CONTROL_VALUESRETURNFILTER
 		LDAP_CONTROL_VALUESRETURNFILTER,
#endif
		NULL
	};

	bi->bi_controls = controls;

	Debug( LDAP_DEBUG_TRACE,"==>backsql_initialize()\n", 0, 0, 0 );
	
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = backsql_db_init;
	bi->bi_db_config = backsql_db_config;
	bi->bi_db_open = backsql_db_open;
	bi->bi_db_close = backsql_db_close;
	bi->bi_db_destroy = backsql_db_destroy;

#ifdef BACKSQL_ALL_DONE
	bi->bi_op_abandon = backsql_abandon;
	bi->bi_op_compare = backsql_compare;
#else
	bi->bi_op_abandon = 0;
	bi->bi_op_compare = 0;
#endif
	bi->bi_op_bind = backsql_bind;
	bi->bi_op_unbind = backsql_unbind;
	bi->bi_op_search = backsql_search;
	bi->bi_op_modify = backsql_modify;
	bi->bi_op_modrdn = backsql_modrdn;
	bi->bi_op_add = backsql_add;
	bi->bi_op_delete = backsql_delete;
	
	bi->bi_acl_group = 0;
	bi->bi_acl_attribute = 0;
	bi->bi_chk_referrals = 0;
	bi->bi_operational = backsql_operational;
 
	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = backsql_connection_destroy;
	
	Debug( LDAP_DEBUG_TRACE,"<==backsql_initialize()\n", 0, 0, 0 );
	return 0;
}


int
backsql_destroy( 
	BackendInfo 	*bi )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_destroy()\n", 0, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_destroy()\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_init(
	BackendDB 	*bd )
{
	backsql_info *si;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_init()\n", 0, 0, 0 );
	si = (backsql_info *)ch_calloc( 1, sizeof( backsql_info ) );
	memset( si, '\0', sizeof( backsql_info ) );
	ldap_pvt_thread_mutex_init( &si->dbconn_mutex );
	ldap_pvt_thread_mutex_init( &si->schema_mutex );
	backsql_init_db_env( si );

	bd->be_private = si;
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_init()\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_destroy(
	BackendDB 	*bd )
{
	backsql_info *si = (backsql_info*)bd->be_private;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_destroy()\n", 0, 0, 0 );
	ldap_pvt_thread_mutex_lock( &si->dbconn_mutex );
	backsql_free_db_env( si );
	ldap_pvt_thread_mutex_unlock( &si->dbconn_mutex );
	ldap_pvt_thread_mutex_destroy( &si->dbconn_mutex );
	ldap_pvt_thread_mutex_lock( &si->schema_mutex );
	backsql_destroy_schema_map( si );
	ldap_pvt_thread_mutex_unlock( &si->schema_mutex );
	ldap_pvt_thread_mutex_destroy( &si->schema_mutex );
	free( si->dbname );
	free( si->dbuser );
	if ( si->dbpasswd ) {
		free( si->dbpasswd );
	}
	if ( si->dbhost ) {
		free( si->dbhost );
	}
	if ( si->upper_func.bv_val ) {
		free( si->upper_func.bv_val );
		free( si->upper_func_open.bv_val );
		free( si->upper_func_close.bv_val );
	}
	
	free( si->subtree_cond.bv_val );
	free( si->oc_query );
	free( si->at_query );
	free( si->insentry_query );
	free( si->delentry_query );
	free( si );
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_destroy()\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_open(
	BackendDB 	*bd )
{
	backsql_info 	*si = (backsql_info*)bd->be_private;
	Connection 	tmp;
	SQLHDBC 	dbh;
	ber_len_t	idq_len;
	struct berval	bv;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_open(): "
		"testing RDBMS connection\n", 0, 0, 0 );
	if ( si->dbname == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"datasource name not specified "
			"(use \"dbname\" directive in slapd.conf)\n", 0, 0, 0 );
		return 1;
	}

	if ( si->concat_func == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"concat func not specified (use \"concat_pattern\" "
			"directive in slapd.conf)\n", 0, 0, 0 );

		if ( backsql_split_pattern( backsql_def_concat_func, 
				&si->concat_func, 2 ) ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
				"unable to parse pattern '%s'",
				backsql_def_concat_func, 0, 0 );
			return 1;
		}
	}

	/*
	 * Prepare cast string as required
	 */
	if ( si->upper_func.bv_val ) {
		char buf[1024];

		if ( BACKSQL_UPPER_NEEDS_CAST( si ) ) {
			snprintf( buf, sizeof( buf ), 
				"%s(cast (" /* ? as varchar(%d))) */ , 
				si->upper_func.bv_val );
			ber_str2bv( buf, 0, 1, &si->upper_func_open );

			snprintf( buf, sizeof( buf ),
				/* (cast(? */ " as varchar(%d)))",
				BACKSQL_MAX_DN_LEN );
			ber_str2bv( buf, 0, 1, &si->upper_func_close );

		} else {
			snprintf( buf, sizeof( buf ), "%s(" /* ?) */ ,
					si->upper_func.bv_val );
			ber_str2bv( buf, 0, 1, &si->upper_func_open );

			ber_str2bv( /* (? */ ")", 0, 1, &si->upper_func_close );
		}
	}
	
	if ( si->dbuser == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"user name not specified "
			"(use \"dbuser\" directive in slapd.conf)\n", 0, 0, 0 );
		return 1;
	}
	
	if ( si->subtree_cond.bv_val == NULL ) {
		/*
		 * Prepare concat function for subtree search condition
		 */
		struct berval	concat;
		ber_len_t	len = 0;
		struct berval	values[] = {
			{ sizeof( "'%'" ) - 1,	"'%'" },
			{ sizeof( "?" ) - 1,	"?" },
			{ 0,			NULL }
		};

		if ( backsql_prepare_pattern( si->concat_func, values, 
				&concat ) ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
				"unable to prepare CONCAT pattern", 0, 0, 0 );
			return 1;
		}
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"subtree search SQL condition not specified "
			"(use \"subtree_cond\" directive in slapd.conf)\n", 
			0, 0, 0);

		si->subtree_cond.bv_val = NULL;
		si->subtree_cond.bv_len = 0;

		if ( si->upper_func.bv_val ) {

			/*
			 * UPPER(ldap_entries.dn) LIKE UPPER(CONCAT('%',?))
			 */

			backsql_strfcat( &si->subtree_cond, &len, "blbbb",
					&si->upper_func,
					(ber_len_t)sizeof( "(ldap_entries.dn) LIKE " ) - 1,
						"(ldap_entries.dn) LIKE ",
					&si->upper_func_open,
					&concat,
					&si->upper_func_close );

		} else {

			/*
			 * ldap_entries.dn LIKE CONCAT('%',?)
			 */

			backsql_strfcat( &si->subtree_cond, &len, "lb",
					(ber_len_t)sizeof( "ldap_entries.dn LIKE " ) - 1,
						"ldap_entries.dn LIKE ",
					&concat );
		}
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' as default\n",
			si->subtree_cond.bv_val, 0, 0 );
	}

	if ( si->children_cond.bv_val == NULL ) {
		ber_len_t	len = 0;

		if ( si->upper_func.bv_val ) {

			/*
			 * UPPER(ldap_entries.dn) LIKE UPPER(CONCAT('%,',?))
			 */

			backsql_strfcat( &si->children_cond, &len, "blbl",
					&si->upper_func,
					(ber_len_t)sizeof( "(ldap_entries.dn)=" ) - 1,
						"(ldap_entries.dn)=",
					&si->upper_func,
					(ber_len_t)sizeof( "(?)" ) - 1, "(?)" );

		} else {

			/*
			 * ldap_entries.dn LIKE CONCAT('%,',?)
			 */

			backsql_strfcat( &si->children_cond, &len, "l",
					(ber_len_t)sizeof( "ldap_entries.dn=?" ) - 1,
						"ldap_entries.dn=?");
		}
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' as default\n",
			si->children_cond.bv_val, 0, 0 );
	}

	if ( si->oc_query == NULL ) {
		if ( BACKSQL_CREATE_NEEDS_SELECT( si ) ) {
			si->oc_query =
				ch_strdup( backsql_def_needs_select_oc_query );

		} else {
			si->oc_query = ch_strdup( backsql_def_oc_query );
		}

		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"objectclass mapping SQL statement not specified "
			"(use \"oc_query\" directive in slapd.conf)\n", 
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' by default\n", si->oc_query, 0, 0 );
	}
	
	if ( si->at_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"attribute mapping SQL statement not specified "
			"(use \"at_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug(LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' by default\n",
			backsql_def_at_query, 0, 0 );
		si->at_query = ch_strdup( backsql_def_at_query );
	}
	
	if ( si->insentry_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"entry insertion SQL statement not specified "
			"(use \"insentry_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug(LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' by default\n",
			backsql_def_insentry_query, 0, 0 );
		si->insentry_query = ch_strdup( backsql_def_insentry_query );
	}
	
	if ( si->delentry_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"entry deletion SQL statement not specified "
			"(use \"delentry_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting '%s' by default\n",
			backsql_def_delentry_query, 0, 0 );
		si->delentry_query = ch_strdup( backsql_def_delentry_query );
	}


	tmp.c_connid =- 1;
	if ( backsql_get_db_conn( bd, &tmp, &dbh ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"connection failed, exiting\n", 0, 0, 0 );
		return 1;
	}

	/*
	 * Prepare ID selection query
	 */
	si->id_query = NULL;
	idq_len = 0;

	bv.bv_val = NULL;
	bv.bv_len = 0;
	if ( si->upper_func.bv_val == NULL ) {
		backsql_strcat( &bv, &idq_len, backsql_id_query, 
				"dn=?", NULL );
	} else {
		if ( BACKSQL_HAS_LDAPINFO_DN_RU( si ) ) {
			backsql_strcat( &bv, &idq_len, backsql_id_query,
					"dn_ru=?", NULL );
		} else {
			if ( BACKSQL_USE_REVERSE_DN( si ) ) {
				backsql_strfcat( &bv, &idq_len, "sbl",
						backsql_id_query,
						&si->upper_func, 
						(ber_len_t)sizeof( "(dn)=?" ) - 1, "(dn)=?" );
			} else {
				backsql_strfcat( &bv, &idq_len, "sblbcb",
						backsql_id_query,
						&si->upper_func, 
						(ber_len_t)sizeof( "(dn)=" ) - 1, "(dn)=",
						&si->upper_func_open, 
						'?', 
						&si->upper_func_close );
			}
		}
	}
	si->id_query = bv.bv_val;

       	/*
	 * Prepare children ID selection query
	 */
	si->has_children_query = NULL;
	idq_len = 0;

	bv.bv_val = NULL;
	bv.bv_len = 0;
	backsql_strfcat( &bv, &idq_len, "sb",
			"SELECT COUNT(distinct subordinates.id) FROM ldap_entries,ldap_entries AS subordinates WHERE subordinates.parent=ldap_entries.id AND ",

			&si->children_cond );
	si->has_children_query = bv.bv_val;
 
	backsql_free_db_conn( bd, &tmp );
	if ( !BACKSQL_SCHEMA_LOADED( si ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"test failed, schema map not loaded - exiting\n",
			0, 0, 0 );
		return 1;
	}
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_open(): "
		"test succeeded, schema map loaded\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_close(
	BackendDB	*bd )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_close()\n", 0, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_close()\n", 0, 0, 0 );
	return 0;
}

int
backsql_connection_destroy(
	BackendDB 	*be,
	Connection 	*conn )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_connection_destroy()\n", 0, 0, 0 );
	backsql_free_db_conn( be, conn );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_connection_destroy()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */


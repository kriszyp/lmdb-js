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
#include "ac/string.h"

#include "slap.h"
#include "proto-sql.h"
#include "external.h"

#if SLAPD_SQL == SLAPD_MOD_DYNAMIC

int
init_module(
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

#endif /* SLAPD_SQL == SLAPD_MOD_DYNAMIC */

int
sql_back_initialize(
	BackendInfo	*bi )
{ 
	static char *controls[] = {
#if 0 /* needs updating */
#ifdef LDAP_CONTROL_NOOP
		LDAP_CONTROL_NOOP,
#endif /* LDAP_CONTROL_NOOP */
#endif
#ifdef LDAP_CONTROL_VALUESRETURNFILTER
 		LDAP_CONTROL_VALUESRETURNFILTER,
#endif /* LDAP_CONTROL_VALUESRETURNFILTER */
		NULL
	};

	bi->bi_controls = controls;

	Debug( LDAP_DEBUG_TRACE,"==>sql_back_initialize()\n", 0, 0, 0 );
	
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = backsql_db_init;
	bi->bi_db_config = backsql_db_config;
	bi->bi_db_open = backsql_db_open;
	bi->bi_db_close = backsql_db_close;
	bi->bi_db_destroy = backsql_db_destroy;

	bi->bi_op_abandon = 0;
	bi->bi_op_compare = backsql_compare;
	bi->bi_op_bind = backsql_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = backsql_search;
	bi->bi_op_modify = backsql_modify;
	bi->bi_op_modrdn = backsql_modrdn;
	bi->bi_op_add = backsql_add;
	bi->bi_op_delete = backsql_delete;
	
	bi->bi_chk_referrals = 0;
	bi->bi_operational = backsql_operational;
 
	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = backsql_connection_destroy;

	Debug( LDAP_DEBUG_TRACE,"<==sql_back_initialize()\n", 0, 0, 0 );
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
	backsql_info	*bi;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_init()\n", 0, 0, 0 );
	bi = (backsql_info *)ch_calloc( 1, sizeof( backsql_info ) );
	memset( bi, '\0', sizeof( backsql_info ) );
	ldap_pvt_thread_mutex_init( &bi->sql_dbconn_mutex );
	ldap_pvt_thread_mutex_init( &bi->sql_schema_mutex );
	backsql_init_db_env( bi );

	bd->be_private = bi;
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_init()\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_destroy(
	BackendDB 	*bd )
{
	backsql_info	*bi = (backsql_info*)bd->be_private;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_destroy()\n", 0, 0, 0 );
	ldap_pvt_thread_mutex_lock( &bi->sql_dbconn_mutex );
	backsql_free_db_env( bi );
	ldap_pvt_thread_mutex_unlock( &bi->sql_dbconn_mutex );
	ldap_pvt_thread_mutex_destroy( &bi->sql_dbconn_mutex );
	ldap_pvt_thread_mutex_lock( &bi->sql_schema_mutex );
	backsql_destroy_schema_map( bi );
	ldap_pvt_thread_mutex_unlock( &bi->sql_schema_mutex );
	ldap_pvt_thread_mutex_destroy( &bi->sql_schema_mutex );
	free( bi->sql_dbname );
	free( bi->sql_dbuser );
	if ( bi->sql_dbpasswd ) {
		free( bi->sql_dbpasswd );
	}
	if ( bi->sql_dbhost ) {
		free( bi->sql_dbhost );
	}
	if ( bi->sql_upper_func.bv_val ) {
		free( bi->sql_upper_func.bv_val );
		free( bi->sql_upper_func_open.bv_val );
		free( bi->sql_upper_func_close.bv_val );
	}
	
	free( bi->sql_subtree_cond.bv_val );
	free( bi->sql_oc_query );
	free( bi->sql_at_query );
	free( bi->sql_insentry_query );
	free( bi->sql_delentry_query );
	free( bi->sql_delobjclasses_query );
	free( bi->sql_delreferrals_query );

	if ( bi->sql_baseObject ) {
		entry_free( bi->sql_baseObject );
	}
	
	free( bi );
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_db_destroy()\n", 0, 0, 0 );
	return 0;
}

int
backsql_db_open(
	BackendDB 	*bd )
{
	backsql_info 	*bi = (backsql_info*)bd->be_private;
	SQLHDBC 	dbh;
	ber_len_t	idq_len;
	struct berbuf	bb = BB_NULL;

	Operation	otmp = { 0 };
		
	Debug( LDAP_DEBUG_TRACE, "==>backsql_db_open(): "
		"testing RDBMS connection\n", 0, 0, 0 );
	if ( bi->sql_dbname == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"datasource name not specified "
			"(use \"dbname\" directive in slapd.conf)\n", 0, 0, 0 );
		return 1;
	}

	if ( bi->sql_concat_func == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"concat func not specified (use \"concat_pattern\" "
			"directive in slapd.conf)\n", 0, 0, 0 );

		if ( backsql_split_pattern( backsql_def_concat_func, 
				&bi->sql_concat_func, 2 ) ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
				"unable to parse pattern \"%s\"",
				backsql_def_concat_func, 0, 0 );
			return 1;
		}
	}

	/*
	 * Prepare cast string as required
	 */
	if ( bi->sql_upper_func.bv_val ) {
		char buf[1024];

		if ( BACKSQL_UPPER_NEEDS_CAST( bi ) ) {
			snprintf( buf, sizeof( buf ), 
				"%s(cast (" /* ? as varchar(%d))) */ , 
				bi->sql_upper_func.bv_val );
			ber_str2bv( buf, 0, 1, &bi->sql_upper_func_open );

			snprintf( buf, sizeof( buf ),
				/* (cast(? */ " as varchar(%d)))",
				BACKSQL_MAX_DN_LEN );
			ber_str2bv( buf, 0, 1, &bi->sql_upper_func_close );

		} else {
			snprintf( buf, sizeof( buf ), "%s(" /* ?) */ ,
					bi->sql_upper_func.bv_val );
			ber_str2bv( buf, 0, 1, &bi->sql_upper_func_open );

			ber_str2bv( /* (? */ ")", 0, 1, &bi->sql_upper_func_close );
		}
	}

	/* normalize filter values only if necessary */
	bi->sql_caseIgnoreMatch = mr_find( "caseIgnoreMatch" );
	assert( bi->sql_caseIgnoreMatch );

	bi->sql_telephoneNumberMatch = mr_find( "telephoneNumberMatch" );
	assert( bi->sql_telephoneNumberMatch );

	if ( bi->sql_dbuser == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"user name not specified "
			"(use \"dbuser\" directive in slapd.conf)\n", 0, 0, 0 );
		return 1;
	}
	
	if ( bi->sql_subtree_cond.bv_val == NULL ) {
		/*
		 * Prepare concat function for subtree search condition
		 */
		struct berval	concat;
		struct berval	values[] = {
			BER_BVC( "'%'" ),
			BER_BVC( "?" ),
			BER_BVNULL
		};
		struct berbuf	bb = BB_NULL;

		if ( backsql_prepare_pattern( bi->sql_concat_func, values, 
				&concat ) ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
				"unable to prepare CONCAT pattern", 0, 0, 0 );
			return 1;
		}
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"subtree search SQL condition not specified "
			"(use \"subtree_cond\" directive in slapd.conf)\n", 
			0, 0, 0);

		if ( bi->sql_upper_func.bv_val ) {

			/*
			 * UPPER(ldap_entries.dn) LIKE UPPER(CONCAT('%',?))
			 */

			backsql_strfcat( &bb, "blbbb",
					&bi->sql_upper_func,
					(ber_len_t)STRLENOF( "(ldap_entries.dn) LIKE " ),
						"(ldap_entries.dn) LIKE ",
					&bi->sql_upper_func_open,
					&concat,
					&bi->sql_upper_func_close );

		} else {

			/*
			 * ldap_entries.dn LIKE CONCAT('%',?)
			 */

			backsql_strfcat( &bb, "lb",
					(ber_len_t)STRLENOF( "ldap_entries.dn LIKE " ),
						"ldap_entries.dn LIKE ",
					&concat );
		}

		bi->sql_subtree_cond = bb.bb_val;
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" as default\n",
			bi->sql_subtree_cond.bv_val, 0, 0 );
	}

	if ( bi->sql_children_cond.bv_val == NULL ) {
		struct berbuf	bb = BB_NULL;

		if ( bi->sql_upper_func.bv_val ) {

			/*
			 * UPPER(ldap_entries.dn) LIKE UPPER(CONCAT('%,',?))
			 */

			backsql_strfcat( &bb, "blbl",
					&bi->sql_upper_func,
					(ber_len_t)STRLENOF( "(ldap_entries.dn)=" ),
						"(ldap_entries.dn)=",
					&bi->sql_upper_func,
					(ber_len_t)STRLENOF( "(?)" ), "(?)" );

		} else {

			/*
			 * ldap_entries.dn LIKE CONCAT('%,',?)
			 */

			backsql_strfcat( &bb, "l",
					(ber_len_t)STRLENOF( "ldap_entries.dn=?" ),
						"ldap_entries.dn=?");
		}

		bi->sql_children_cond = bb.bb_val;
			
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" as default\n",
			bi->sql_children_cond.bv_val, 0, 0 );
	}

	if ( bi->sql_oc_query == NULL ) {
		if ( BACKSQL_CREATE_NEEDS_SELECT( bi ) ) {
			bi->sql_oc_query =
				ch_strdup( backsql_def_needs_select_oc_query );

		} else {
			bi->sql_oc_query = ch_strdup( backsql_def_oc_query );
		}

		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"objectclass mapping SQL statement not specified "
			"(use \"oc_query\" directive in slapd.conf)\n", 
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n", bi->sql_oc_query, 0, 0 );
	}
	
	if ( bi->sql_at_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"attribute mapping SQL statement not specified "
			"(use \"at_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug(LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n",
			backsql_def_at_query, 0, 0 );
		bi->sql_at_query = ch_strdup( backsql_def_at_query );
	}
	
	if ( bi->sql_insentry_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"entry insertion SQL statement not specified "
			"(use \"insentry_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug(LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n",
			backsql_def_insentry_query, 0, 0 );
		bi->sql_insentry_query = ch_strdup( backsql_def_insentry_query );
	}
	
	if ( bi->sql_delentry_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"entry deletion SQL statement not specified "
			"(use \"delentry_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n",
			backsql_def_delentry_query, 0, 0 );
		bi->sql_delentry_query = ch_strdup( backsql_def_delentry_query );
	}

	if ( bi->sql_delobjclasses_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"objclasses deletion SQL statement not specified "
			"(use \"delobjclasses_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n",
			backsql_def_delobjclasses_query, 0, 0 );
		bi->sql_delobjclasses_query = ch_strdup( backsql_def_delobjclasses_query );
	}

	if ( bi->sql_delreferrals_query == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"referrals deletion SQL statement not specified "
			"(use \"delreferrals_query\" directive in slapd.conf)\n",
			0, 0, 0 );
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"setting \"%s\" by default\n",
			backsql_def_delreferrals_query, 0, 0 );
		bi->sql_delreferrals_query = ch_strdup( backsql_def_delreferrals_query );
	}

	otmp.o_connid = (unsigned long)(-1);
	otmp.o_bd = bd;
	if ( backsql_get_db_conn( &otmp, &dbh ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_db_open(): "
			"connection failed, exiting\n", 0, 0, 0 );
		return 1;
	}

	/*
	 * Prepare ID selection query
	 */
	bi->sql_id_query = NULL;
	idq_len = 0;

	if ( bi->sql_upper_func.bv_val == NULL ) {
		backsql_strcat( &bb, backsql_id_query, "dn=?", NULL );

	} else {
		if ( BACKSQL_HAS_LDAPINFO_DN_RU( bi ) ) {
			backsql_strcat( &bb, backsql_id_query,
					"dn_ru=?", NULL );
		} else {
			if ( BACKSQL_USE_REVERSE_DN( bi ) ) {
				backsql_strfcat( &bb, "sbl",
						backsql_id_query,
						&bi->sql_upper_func, 
						(ber_len_t)STRLENOF( "(dn)=?" ), "(dn)=?" );
			} else {
				backsql_strfcat( &bb, "sblbcb",
						backsql_id_query,
						&bi->sql_upper_func, 
						(ber_len_t)STRLENOF( "(dn)=" ), "(dn)=",
						&bi->sql_upper_func_open, 
						'?', 
						&bi->sql_upper_func_close );
			}
		}
	}
	bi->sql_id_query = bb.bb_val.bv_val;

       	/*
	 * Prepare children ID selection query
	 */
	bi->sql_has_children_query = NULL;

	bb.bb_val.bv_val = NULL;
	bb.bb_val.bv_len = 0;
	bb.bb_len = 0;
	backsql_strfcat( &bb, "sb",
			"SELECT COUNT(distinct subordinates.id) FROM ldap_entries,ldap_entries subordinates WHERE subordinates.parent=ldap_entries.id AND ",

			&bi->sql_children_cond );
	bi->sql_has_children_query = bb.bb_val.bv_val;
 
	backsql_free_db_conn( &otmp );
	if ( !BACKSQL_SCHEMA_LOADED( bi ) ) {
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
backsql_connection_destroy( Backend *bd, Connection *c )
{
	Operation o = { 0 };
	o.o_bd = bd;
	o.o_connid = c->c_connid;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_connection_destroy()\n", 0, 0, 0 );
	backsql_free_db_conn( &o );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_connection_destroy()\n", 0, 0, 0 );

	return 0;
}

#endif /* SLAPD_SQL */


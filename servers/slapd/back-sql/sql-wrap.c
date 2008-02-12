/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
 * Portions Copyright 2002 Pierangelo Masarati.
 * Portions Copyright 2004 Mark Adamson.
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
 * Pierangelo Masarati and Mark Adamson.
 */

#include "portable.h"

#include <stdio.h>
#include "ac/string.h"
#include <sys/types.h>

#include "slap.h"
#include "proto-sql.h"

#define MAX_ATTR_LEN 16384

typedef struct backsql_db_conn {
	unsigned long	ldap_cid;
	SQLHDBC		dbh;
} backsql_db_conn;

void
backsql_PrintErrors( SQLHENV henv, SQLHDBC hdbc, SQLHSTMT sth, int rc )
{
	SQLCHAR	msg[SQL_MAX_MESSAGE_LENGTH];		/* msg. buffer    */
	SQLCHAR	state[SQL_SQLSTATE_SIZE];		/* statement buf. */
	SDWORD	iSqlCode;				/* return code    */
	SWORD	len = SQL_MAX_MESSAGE_LENGTH - 1;	/* return length  */ 

	Debug( LDAP_DEBUG_TRACE, "Return code: %d\n", rc, 0, 0 );

	for ( ; rc = SQLError( henv, hdbc, sth, state, &iSqlCode, msg,
		SQL_MAX_MESSAGE_LENGTH - 1, &len ), BACKSQL_SUCCESS( rc ); )
	{
		Debug( LDAP_DEBUG_TRACE,
			"   nativeErrCode=%d SQLengineState=%s msg=\"%s\"\n",
			(int)iSqlCode, state, msg );
	}
}

RETCODE
backsql_Prepare( SQLHDBC dbh, SQLHSTMT *sth, char *query, int timeout )
{
	RETCODE		rc;

	rc = SQLAllocStmt( dbh, sth );
	if ( rc != SQL_SUCCESS ) {
		return rc;
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "==>backsql_Prepare()\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */

#ifdef BACKSQL_MSSQL_WORKAROUND
	{
		char		drv_name[ 30 ];
		SWORD		len;

		SQLGetInfo( dbh, SQL_DRIVER_NAME, drv_name, sizeof( drv_name ), &len );

#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, "backsql_Prepare(): driver name=\"%s\"\n",
				drv_name, 0, 0 );
#endif /* BACKSQL_TRACE */

		ldap_pvt_str2upper( drv_name );
		if ( !strncmp( drv_name, "SQLSRV32.DLL", STRLENOF( "SQLSRV32.DLL" ) ) ) {
			/*
			 * stupid default result set in MS SQL Server
			 * does not support multiple active statements
			 * on the same connection -- so we are trying 
			 * to make it not to use default result set...
			 */
			Debug( LDAP_DEBUG_TRACE, "_SQLprepare(): "
				"enabling MS SQL Server default result "
				"set workaround\n", 0, 0, 0 );
			rc = SQLSetStmtOption( *sth, SQL_CONCURRENCY, 
					SQL_CONCUR_ROWVER );
			if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_Prepare(): "
					"SQLSetStmtOption(SQL_CONCURRENCY,"
					"SQL_CONCUR_ROWVER) failed:\n", 
					0, 0, 0 );
				backsql_PrintErrors( SQL_NULL_HENV, dbh, *sth, rc );
				SQLFreeStmt( *sth, SQL_DROP );
				return rc;
			}
		}
	}
#endif /* BACKSQL_MSSQL_WORKAROUND */

	if ( timeout > 0 ) {
		Debug( LDAP_DEBUG_TRACE, "_SQLprepare(): "
			"setting query timeout to %d sec.\n", 
			timeout, 0, 0 );
		rc = SQLSetStmtOption( *sth, SQL_QUERY_TIMEOUT, timeout );
		if ( rc != SQL_SUCCESS ) {
			backsql_PrintErrors( SQL_NULL_HENV, dbh, *sth, rc );
			SQLFreeStmt( *sth, SQL_DROP );
			return rc;
		}
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<==backsql_Prepare() calling SQLPrepare()\n",
			0, 0, 0 );
#endif /* BACKSQL_TRACE */

	return SQLPrepare( *sth, (SQLCHAR *)query, SQL_NTS );
}

RETCODE
backsql_BindRowAsStrings_x( SQLHSTMT sth, BACKSQL_ROW_NTS *row, void *ctx )
{
	RETCODE		rc;
	SQLCHAR		colname[ 64 ];
	SQLSMALLINT	name_len, col_type, col_scale, col_null;
	UDWORD		col_prec;
	int		i;

	if ( row == NULL ) {
		return SQL_ERROR;
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "==> backsql_BindRowAsStrings()\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */
	
	rc = SQLNumResultCols( sth, &row->ncols );
	if ( rc != SQL_SUCCESS ) {
#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, "backsql_BindRowAsStrings(): "
			"SQLNumResultCols() failed:\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */
		
		backsql_PrintErrors( SQL_NULL_HENV, SQL_NULL_HDBC, sth, rc );

	} else {
#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, "backsql_BindRowAsStrings: "
			"ncols=%d\n", (int)row->ncols, 0, 0 );
#endif /* BACKSQL_TRACE */

		row->col_names = (BerVarray)ber_memcalloc_x( row->ncols + 1, 
				sizeof( struct berval ), ctx );
		if ( !row->col_names ) goto nomem3;
		row->cols = (char **)ber_memcalloc_x( row->ncols + 1, 
				sizeof( char * ), ctx );
		if ( !row->cols ) goto nomem2;
		row->col_prec = (UDWORD *)ber_memcalloc_x( row->ncols,
				sizeof( UDWORD ), ctx );
		if ( !row->col_prec ) goto nomem1;
		row->value_len = (SQLINTEGER *)ber_memcalloc_x( row->ncols,
				sizeof( SQLINTEGER ), ctx );
		if ( !row->value_len ) {
			ber_memfree_x( row->col_prec, ctx );
			row->col_prec = NULL;
nomem1:		ber_memfree_x( row->cols, ctx );
			row->cols = NULL;
nomem2:		ber_memfree_x( row->col_names, ctx );
			row->col_names = NULL;
nomem3:		Debug( LDAP_DEBUG_ANY, "backsql_BindRowAsStrings: "
				"out of memory\n", 0, 0, 0 );
			return LDAP_NO_MEMORY;
		}
		for ( i = 1; i <= row->ncols; i++ ) {
			rc = SQLDescribeCol( sth, (SQLSMALLINT)i, &colname[ 0 ],
					(SQLUINTEGER)( sizeof( colname ) - 1 ),
					&name_len, &col_type,
					&col_prec, &col_scale, &col_null );
			/* FIXME: test rc? */

			ber_str2bv_x( (char *)colname, 0, 1,
					&row->col_names[ i - 1 ], ctx );
#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, "backsql_BindRowAsStrings: "
				"col_name=%s, col_prec[%d]=%d\n",
				colname, (int)i, (int)col_prec );
#endif /* BACKSQL_TRACE */
			if ( col_type != SQL_CHAR && col_type != SQL_VARCHAR )
			{
				col_prec = MAX_ATTR_LEN;
			}

			row->cols[ i - 1 ] = (char *)ber_memcalloc_x( col_prec + 1,
					sizeof( char ), ctx );
			row->col_prec[ i - 1 ] = col_prec;
			rc = SQLBindCol( sth, (SQLUSMALLINT)i,
					 SQL_C_CHAR,
					 (SQLPOINTER)row->cols[ i - 1 ],
					 col_prec + 1,
					 &row->value_len[ i - 1 ] );
			/* FIXME: test rc? */
		}

		BER_BVZERO( &row->col_names[ i - 1 ] );
		row->cols[ i - 1 ] = NULL;
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<== backsql_BindRowAsStrings()\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */

	return rc;
}

RETCODE
backsql_BindRowAsStrings( SQLHSTMT sth, BACKSQL_ROW_NTS *row )
{
	return backsql_BindRowAsStrings_x( sth, row, NULL );
}

RETCODE
backsql_FreeRow_x( BACKSQL_ROW_NTS *row, void *ctx )
{
	if ( row->cols == NULL ) {
		return SQL_ERROR;
	}

	ber_bvarray_free_x( row->col_names, ctx );
	ber_memvfree_x( (void **)row->cols, ctx );
	ber_memfree_x( row->col_prec, ctx );
	ber_memfree_x( row->value_len, ctx );

	return SQL_SUCCESS;
}


RETCODE
backsql_FreeRow( BACKSQL_ROW_NTS *row )
{
	return backsql_FreeRow_x( row, NULL );
}

static int
backsql_cmp_connid( const void *v_c1, const void *v_c2 )
{
	const backsql_db_conn *c1 = v_c1, *c2 = v_c2;
	if ( c1->ldap_cid > c2->ldap_cid ) {
		return 1;
	}
	
	if ( c1->ldap_cid < c2->ldap_cid ) {
		return -1;
	}
	
	return 0;
}

static void
backsql_close_db_conn( void *v_conn )
{
	backsql_db_conn	*conn = 	(backsql_db_conn *)v_conn;
	unsigned long	cid = conn->ldap_cid;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_close_db_conn(%lu)\n",
		cid, 0, 0 );

	/*
	 * Default transact is SQL_ROLLBACK; commit is required only
	 * by write operations, and it is explicitly performed after
	 * each atomic operation succeeds.
	 */

	/* TimesTen */
	SQLTransact( SQL_NULL_HENV, conn->dbh, SQL_ROLLBACK );
	SQLDisconnect( conn->dbh );
	SQLFreeConnect( conn->dbh );
	ch_free( conn );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_close_db_conn(%lu)\n",
		cid, 0, 0 );
}

int
backsql_conn_destroy(
	backsql_info	*bi )
{
	avl_free( bi->sql_db_conns, backsql_close_db_conn );

	return 0;
}

int
backsql_init_db_env( backsql_info *bi )
{
	RETCODE		rc;
	int		ret = SQL_SUCCESS;
	
	Debug( LDAP_DEBUG_TRACE, "==>backsql_init_db_env()\n", 0, 0, 0 );

	rc = SQLAllocEnv( &bi->sql_db_env );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "init_db_env: SQLAllocEnv failed:\n",
				0, 0, 0 );
		backsql_PrintErrors( SQL_NULL_HENV, SQL_NULL_HDBC,
				SQL_NULL_HENV, rc );
		ret = SQL_ERROR;
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_init_db_env()=%d\n", ret, 0, 0 );

	return ret;
}

int
backsql_free_db_env( backsql_info *bi )
{
	Debug( LDAP_DEBUG_TRACE, "==>backsql_free_db_env()\n", 0, 0, 0 );

	(void)SQLFreeEnv( bi->sql_db_env );
	bi->sql_db_env = SQL_NULL_HENV;

	/*
	 * stop, if frontend waits for all threads to shutdown 
	 * before calling this -- then what are we going to delete?? 
	 * everything is already deleted...
	 */
	Debug( LDAP_DEBUG_TRACE, "<==backsql_free_db_env()\n", 0, 0, 0 );

	return SQL_SUCCESS;
}

static int
backsql_open_db_conn( backsql_info *bi, unsigned long ldap_cid, backsql_db_conn **pdbc )
{
	/* TimesTen */
	char			DBMSName[ 32 ];
	SQLHDBC			dbh = SQL_NULL_HDBC;
	backsql_db_conn		*dbc;
	int			rc;

	assert( pdbc != NULL );
	*pdbc = NULL;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_open_db_conn(%lu)\n",
		ldap_cid, 0, 0 );

	rc = SQLAllocConnect( bi->sql_db_env, &dbh );
	if ( !BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
			"SQLAllocConnect() failed:\n", ldap_cid, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, SQL_NULL_HDBC,
				SQL_NULL_HENV, rc );
		return LDAP_UNAVAILABLE;
	}

	rc = SQLConnect( dbh,
			(SQLCHAR*)bi->sql_dbname, SQL_NTS,
			(SQLCHAR*)bi->sql_dbuser, SQL_NTS,
			(SQLCHAR*)bi->sql_dbpasswd, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
			"SQLConnect() to database \"%s\" %s.\n",
			ldap_cid, bi->sql_dbname,
			rc == SQL_SUCCESS_WITH_INFO ?
			"succeeded with info" : "failed" );
		backsql_PrintErrors( bi->sql_db_env, dbh, SQL_NULL_HENV, rc );
		if ( rc != SQL_SUCCESS_WITH_INFO ) {
			SQLFreeConnect( dbh );
			return LDAP_UNAVAILABLE;
		}
	}

	/* 
	 * TimesTen : Turn off autocommit.  We must explicitly
	 * commit any transactions. 
	 */
	SQLSetConnectOption( dbh, SQL_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF );

	/* 
	 * See if this connection is to TimesTen.  If it is,
	 * remember that fact for later use.
	 */
	/* Assume until proven otherwise */
	bi->sql_flags &= ~BSQLF_USE_REVERSE_DN;
	DBMSName[ 0 ] = '\0';
	rc = SQLGetInfo( dbh, SQL_DBMS_NAME, (PTR)&DBMSName,
			sizeof( DBMSName ), NULL );
	if ( rc == SQL_SUCCESS ) {
		if ( strcmp( DBMSName, "TimesTen" ) == 0 ||
				strcmp( DBMSName, "Front-Tier" ) == 0 ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
				"TimesTen database!\n", ldap_cid, 0, 0 );
			bi->sql_flags |= BSQLF_USE_REVERSE_DN;
		}

	} else {
		Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
			"SQLGetInfo() failed.\n", ldap_cid, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, SQL_NULL_HENV, rc );
	}
	/* end TimesTen */

	dbc = (backsql_db_conn *)ch_calloc( 1, sizeof( backsql_db_conn ) );
	dbc->ldap_cid = ldap_cid;
	dbc->dbh = dbh;

	*pdbc = dbc;

	Debug( LDAP_DEBUG_TRACE, "<==backsql_open_db_conn(%lu)\n", ldap_cid, 0, 0 );

	return rc;
}

int
backsql_free_db_conn( Operation *op )
{
	backsql_info		*bi = (backsql_info *)op->o_bd->be_private;
	backsql_db_conn		tmp = { 0 },
				*conn;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_free_db_conn()\n", 0, 0, 0 );
	tmp.ldap_cid = op->o_connid;
	ldap_pvt_thread_mutex_lock( &bi->sql_dbconn_mutex );
	conn = avl_delete( &bi->sql_db_conns, &tmp, backsql_cmp_connid );
	ldap_pvt_thread_mutex_unlock( &bi->sql_dbconn_mutex );

	/*
	 * we have one thread per connection, as I understand -- so we can
	 * get this out of critical section
	 */
	if ( conn != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_free_db_conn(): "
			"closing db connection %lu (%p)\n",
			op->o_connid, (void *)conn, 0 );
		backsql_close_db_conn( (void *)conn );
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_free_db_conn()\n", 0, 0, 0 );

	return conn ? SQL_SUCCESS : SQL_ERROR;
}

int
backsql_get_db_conn( Operation *op, SQLHDBC *dbh )
{
	backsql_info		*bi = (backsql_info *)op->o_bd->be_private;
	backsql_db_conn		*dbc,
				tmp = { 0 };
	int			rc = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_get_db_conn()\n", 0, 0, 0 );

	assert( dbh != NULL );
	*dbh = SQL_NULL_HDBC;

	tmp.ldap_cid = op->o_connid;

	/*
	 * we have one thread per connection, as I understand -- 
	 * so we do not need locking here
	 */
	ldap_pvt_thread_mutex_lock( &bi->sql_dbconn_mutex );
	dbc = avl_find( bi->sql_db_conns, &tmp, backsql_cmp_connid );
	ldap_pvt_thread_mutex_unlock( &bi->sql_dbconn_mutex );
	if ( !dbc ) {
		rc = backsql_open_db_conn( bi, op->o_connid, &dbc );
		if ( rc != LDAP_SUCCESS) {
			Debug( LDAP_DEBUG_TRACE, "backsql_get_db_conn(): "
				"could not get connection handle "
				"-- returning NULL\n", 0, 0, 0 );
			return rc;

		} else {
			int	ret;

			Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
				"connected, adding to tree.\n",
				op->o_connid, 0, 0 );
			ldap_pvt_thread_mutex_lock( &bi->sql_dbconn_mutex );
			ret = avl_insert( &bi->sql_db_conns, dbc, backsql_cmp_connid, avl_dup_error );
			ldap_pvt_thread_mutex_unlock( &bi->sql_dbconn_mutex );
			if ( ret != 0 ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_open_db_conn(%lu): "
					"duplicate connection ID.\n",
					op->o_connid, 0, 0 );
				backsql_close_db_conn( (void *)dbc );
				dbc = NULL;
				return LDAP_OTHER;
			}
		}
	}

	*dbh = dbc->dbh;

	Debug( LDAP_DEBUG_TRACE, "<==backsql_get_db_conn()\n", 0, 0, 0 );

	return LDAP_SUCCESS;
}


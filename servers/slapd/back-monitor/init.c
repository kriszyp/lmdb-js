/* init.c - initialize monitor backend */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from
 *    flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 * 
 * 4. This notice may not be removed or altered.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-monitor.h"

/*
 * used by many functions to add description to entries
 */
AttributeDescription *monitor_ad_desc = NULL;
BackendDB *be_monitor = NULL;

/*
 * subsystem data
 */
struct monitorsubsys monitor_subsys[] = {
	{ 
		SLAPD_MONITOR_LISTENER, SLAPD_MONITOR_LISTENER_NAME, 	
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_listener_init,
		NULL,	/* update */
		NULL,	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_DATABASE, SLAPD_MONITOR_DATABASE_NAME, 	
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_database_init,
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_BACKEND, SLAPD_MONITOR_BACKEND_NAME, 
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_backend_init,
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_THREAD, SLAPD_MONITOR_THREAD_NAME, 	
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		monitor_subsys_thread_init,
		monitor_subsys_thread_update,
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_SASL, SLAPD_MONITOR_SASL_NAME, 	
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_TLS, SLAPD_MONITOR_TLS_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_CONN, SLAPD_MONITOR_CONN_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_VOLATILE_CH,
		monitor_subsys_conn_init,
		monitor_subsys_conn_update,
		monitor_subsys_conn_create,
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_READW, SLAPD_MONITOR_READW_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		NULL,	/* init */
		monitor_subsys_readw_update,
		NULL, 	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_WRITEW, SLAPD_MONITOR_WRITEW_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		NULL,   /* init */
		monitor_subsys_writew_update,
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_LOG, SLAPD_MONITOR_LOG_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_NONE,
		monitor_subsys_log_init,
		NULL,	/* update */
		NULL,   /* create */
		monitor_subsys_log_modify
       	}, { 
		SLAPD_MONITOR_OPS, SLAPD_MONITOR_OPS_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_ops_init,
		monitor_subsys_ops_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_SENT, SLAPD_MONITOR_SENT_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_sent_init,
		monitor_subsys_sent_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_TIME, SLAPD_MONITOR_TIME_NAME,
		{ 0L, NULL }, { 0L, NULL }, { 0L, NULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_time_init,
		monitor_subsys_time_update,
		NULL,   /* create */
		NULL,	/* modify */
	}, { -1, NULL }
};

int
monitor_back_initialize(
	BackendInfo	*bi
)
{
	static char *controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		NULL
	};

	bi->bi_controls = controls;

	bi->bi_init = 0;
	bi->bi_open = monitor_back_open;
	bi->bi_config = monitor_back_config;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = monitor_back_db_init;
	bi->bi_db_config = monitor_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = monitor_back_db_destroy;

	bi->bi_op_bind = monitor_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = monitor_back_search;
	bi->bi_op_compare = monitor_back_compare;
	bi->bi_op_modify = monitor_back_modify;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = 0;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_entry_release_rw = 0;
	bi->bi_acl_group = 0;
	bi->bi_acl_attribute = 0;
	bi->bi_chk_referrals = 0;
	bi->bi_operational = monitor_back_operational;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = 0;
	bi->bi_tool_entry_close = 0;
	bi->bi_tool_entry_first = 0;
	bi->bi_tool_entry_next = 0;
	bi->bi_tool_entry_get = 0;
	bi->bi_tool_entry_put = 0;
	bi->bi_tool_entry_reindex = 0;
	bi->bi_tool_sync = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

int
monitor_back_db_init(
	BackendDB	*be
)
{
	struct monitorinfo 	*mi;
	Entry 			*e, *e_tmp;
	struct monitorentrypriv	*mp;
	int			i, rc;
	char 			buf[1024], *end_of_line;
	struct berval		dn, *ndn;
	const char 		*text;
	struct berval		bv[2];

	/*
	 * database monitor can be defined once only
	 */
	if ( be_monitor ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"only one monitor backend is allowed\n" ));
#else
		Debug( LDAP_DEBUG_ANY,
			"only one monitor backend is allowed\n%s%s%s",
			"", "", "" );
#endif
		return( -1 );
	}
	be_monitor = be;

	/* indicate system schema supported */
	be->be_flags |= SLAP_BFLAG_MONITOR;

	ndn = NULL;
	dn.bv_val = SLAPD_MONITOR_DN;
	dn.bv_len = sizeof( SLAPD_MONITOR_DN ) - 1;

	rc = dnNormalize( NULL, &dn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor DN \"" SLAPD_MONITOR_DN "\" backend is allowed\n" ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor DN \"" SLAPD_MONITOR_DN "\" backend is allowed\n",
			0, 0, 0 );
#endif
		return -1;
	}

	ber_bvecadd( &be->be_suffix, ber_dupbv( NULL, &dn ) );
	ber_bvecadd( &be->be_nsuffix, ndn );

	mi = ( struct monitorinfo * )ch_calloc( sizeof( struct monitorinfo ), 1 );
	ldap_pvt_thread_mutex_init( &mi->mi_cache_mutex );

	if ( slap_str2ad( "description", &monitor_ad_desc, &text ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_back_db_init: %s\n", text ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_backend_init: %s\n%s%s", 
			text, "", "" );
#endif
		return( -1 );
	}

	/*	
	 * Create all the subsystem specific entries
	 */
	e_tmp = NULL;
	for ( i = 0; monitor_subsys[ i ].mss_name != NULL; i++ ) {
		int 		len = strlen( monitor_subsys[ i ].mss_name );
		struct berval	dn;
		int		rc;

		dn.bv_len = len + sizeof( "cn=" ) - 1;
		dn.bv_val = ch_calloc( sizeof( char ), dn.bv_len + 1 );
		strcpy( dn.bv_val, "cn=" );
		strcat( dn.bv_val, monitor_subsys[ i ].mss_name );
		rc = dnPretty2( NULL, &dn, &monitor_subsys[ i ].mss_rdn );
		free( dn.bv_val );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"monitor RDN \"%s\" is invalid\n", 
				dn.bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor RDN \"%s\" is invalid\n", 
				dn.bv_val, 0, 0 );
#endif
			return( -1 );
		}

		dn.bv_len += sizeof( SLAPD_MONITOR_DN ); /* 1 for the , */
		dn.bv_val = ch_malloc( dn.bv_len + 1 );
		strcpy( dn.bv_val , monitor_subsys[ i ].mss_rdn.bv_val );
		strcat( dn.bv_val, "," SLAPD_MONITOR_DN );
		rc = dnPrettyNormal( NULL, &dn, &monitor_subsys[ i ].mss_dn,
			&monitor_subsys[ i ].mss_ndn );
		free( dn.bv_val );
		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"monitor DN \"%s\" is invalid\n", 
				dn.bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor DN \"%s\" is invalid\n", 
				dn.bv_val, 0, 0 );
#endif
			return( -1 );
		}

		snprintf( buf, sizeof( buf ),
				"dn: %s\n"
				SLAPD_MONITOR_OBJECTCLASSES 
				"cn: %s\n",
				monitor_subsys[ i ].mss_dn.bv_val,
				monitor_subsys[ i ].mss_name );
		
		e = str2entry( buf );
		
		if ( e == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"unable to create '%s' entry\n", 
				monitor_subsys[ i ].mss_dn.bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"unable to create '%s' entry\n", 
				monitor_subsys[ i ].mss_dn.bv_val, 0, 0 );
#endif
			return( -1 );
		}

		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_info = &monitor_subsys[ i ];
		mp->mp_children = NULL;
		mp->mp_next = e_tmp;
		mp->mp_flags = monitor_subsys[ i ].mss_flags;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"unable to add entry '%s' to cache\n",
				monitor_subsys[ i ].mss_dn.bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"unable to add entry '%s' to cache\n",
				monitor_subsys[ i ].mss_dn.bv_val, 0, 0 );
#endif
			return -1;
		}

		e_tmp = e;
	}

	/*
	 * creates the "cn=Monitor" entry 
	 */
	snprintf( buf, sizeof( buf ), 
			"dn: " SLAPD_MONITOR_DN "\n"
			"objectClass: top\n"
			"objectClass: monitor\n"
			"objectClass: extensibleObject\n"
			"structuralObjectClass: monitor\n"
			"cn: Monitor" );

	e = str2entry( buf );
	if ( e == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"unable to create '%s' entry\n",
			SLAPD_MONITOR_DN ));
#else
		Debug( LDAP_DEBUG_ANY,
			"unable to create '%s' entry\n%s%s",
			SLAPD_MONITOR_DN, "", "" );
#endif
		return( -1 );
	}
	bv[1].bv_val = NULL;
	bv[0].bv_val = (char *) Versionstr;
	end_of_line = strchr( Versionstr, '\n' );
	if ( end_of_line ) {
		bv[0].bv_len = end_of_line - Versionstr;
	} else {
		bv[0].bv_len = strlen( Versionstr );
	}
	if ( attr_merge( e, monitor_ad_desc, bv ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"unable to add description to '%s' entry\n",
			SLAPD_MONITOR_DN ));
#else
		Debug( LDAP_DEBUG_ANY,
			"unable to add description to '%s' entry\n%s%s",
			SLAPD_MONITOR_DN, "", "" );
#endif
		return( -1 );
	}

	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;

	mp->mp_info = NULL;
	mp->mp_children = e_tmp;
	mp->mp_next = NULL;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"unable to add entry '%s' to cache\n",
			SLAPD_MONITOR_DN ));
#else
		Debug( LDAP_DEBUG_ANY,
			"unable to add entry '%s' to cache\n%s%s",
			SLAPD_MONITOR_DN, "", "" );
#endif
		return -1;
	}

	be->be_private = mi;
	
	return 0;
}

int
monitor_back_open(
	BackendInfo	*bi
)
{
	BackendDB		*be;
	struct monitorsubsys	*ms;
	struct berval dn = { sizeof(SLAPD_MONITOR_DN)-1, SLAPD_MONITOR_DN };
	struct berval ndn;
	int rc;

	/*
	 * adds the monitor backend
	 */
	rc = dnNormalize2( NULL, &dn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor DN \"" SLAPD_MONITOR_DN "\" is invalid\n" ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor DN \"" SLAPD_MONITOR_DN "\" is invalid\n",
			0, 0, 0 );
#endif
		return( -1 );
	}

	be = select_backend( &ndn , 0, 0 );
	free( ndn.bv_val );

	if ( be == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"unable to get monitor backend\n" ));
#else
		Debug( LDAP_DEBUG_ANY,
			"unable to get monitor backend\n", 0, 0, 0 );
#endif
		return( -1 );
	}

	for ( ms = monitor_subsys; ms->mss_name != NULL; ms++ ) {
		if ( ms->mss_init && ( *ms->mss_init )( be ) ) {
			return( -1 );
		}
	}

	return( 0 );
}

int
monitor_back_config(
	BackendInfo	*bi,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	/*
	 * eventually, will hold backend specific configuration parameters
	 */
	return 0;
}

int
monitor_back_db_config(
	Backend     *be,
	const char  *fname,
	int         lineno,
	int         argc,
	char        **argv
)
{
#ifdef NEW_LOGGING
	LDAP_LOG(( "config", LDAP_DEBUG_NOTICE,
		"line %d of file '%s' will be ignored\n", lineno, fname ));
#else
	Debug( LDAP_DEBUG_CONFIG, 
		"line %d of file '%s' will be ignored\n%s", lineno, fname, "" );
#endif
	return( 0 );
}

int
monitor_back_db_destroy(
	BackendDB	*be
)
{
	/*
	 * FIXME: destroys all the data
	 */
	return 0;
}


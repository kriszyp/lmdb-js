/* init.c - initialize monitor backend */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 * 
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

#include "slap.h"
#include "back-monitor.h"

/*
 * used by many functions to add description to entries
 */
AttributeDescription *monitor_ad_desc = NULL;

/*
 * subsystem data
 */
struct monitorsubsys monitor_subsys[] = {
	{ 
		SLAPD_MONITOR_LISTENER, SLAPD_MONITOR_LISTENER_NAME, 	
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		NULL,	/* init */
		NULL,	/* update */
		NULL,	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_DATABASE, SLAPD_MONITOR_DATABASE_NAME, 	
		NULL, NULL, NULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_database_init,
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_BACKEND, SLAPD_MONITOR_BACKEND_NAME, 
		NULL, NULL, NULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_backend_init,
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_THREAD, SLAPD_MONITOR_THREAD_NAME, 	
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		monitor_subsys_thread_init,
		monitor_subsys_thread_update,
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_SASL, SLAPD_MONITOR_SASL_NAME, 	
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_TLS, SLAPD_MONITOR_TLS_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_CONN, SLAPD_MONITOR_CONN_NAME,
		NULL, NULL, NULL,
		MONITOR_F_VOLATILE_CH,
		monitor_subsys_conn_init,
		monitor_subsys_conn_update,
		monitor_subsys_conn_create,
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_READW, SLAPD_MONITOR_READW_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		NULL,	/* init */
		monitor_subsys_readw_update,
		NULL, 	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_WRITEW, SLAPD_MONITOR_WRITEW_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		NULL,   /* init */
		monitor_subsys_writew_update,
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_LOG, SLAPD_MONITOR_LOG_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		monitor_subsys_log_init,
		NULL,	/* update */
		NULL,   /* create */
		monitor_subsys_log_modify
       	}, { 
		SLAPD_MONITOR_OPS, SLAPD_MONITOR_OPS_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		monitor_subsys_ops_init,
		monitor_subsys_ops_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_SENT, SLAPD_MONITOR_SENT_NAME,
		NULL, NULL, NULL,
		MONITOR_F_NONE,
		monitor_subsys_sent_init,
		monitor_subsys_sent_update,
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

	bi->bi_init = NULL;
	bi->bi_open = monitor_back_open;
	bi->bi_config = monitor_back_config;
	bi->bi_close = NULL;
	bi->bi_destroy = NULL;

	bi->bi_db_init = monitor_back_db_init;
	bi->bi_db_config = monitor_back_db_config;
	bi->bi_db_open = NULL;
	bi->bi_db_close = NULL;
	bi->bi_db_destroy = monitor_back_db_destroy;

	bi->bi_op_bind = monitor_back_bind;
	bi->bi_op_unbind = NULL;
	bi->bi_op_search = monitor_back_search;
	bi->bi_op_compare = monitor_back_compare;
	bi->bi_op_modify = monitor_back_modify;
	bi->bi_op_modrdn = NULL;
	bi->bi_op_add = NULL;
	bi->bi_op_delete = NULL;
	bi->bi_op_abandon = monitor_back_abandon;

	bi->bi_extended = NULL;

	bi->bi_entry_release_rw = NULL;
	bi->bi_acl_group = NULL;
	bi->bi_acl_attribute = NULL;
	bi->bi_chk_referrals = NULL;
	bi->bi_operational = monitor_back_operational;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = NULL;
	bi->bi_tool_entry_close = NULL;
	bi->bi_tool_entry_first = NULL;
	bi->bi_tool_entry_next = NULL;
	bi->bi_tool_entry_get = NULL;
	bi->bi_tool_entry_put = NULL;
	bi->bi_tool_entry_reindex = NULL;
	bi->bi_tool_sync = NULL;

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
	int			i;
	char 			buf[1024], *ndn, *end_of_line;
	const char 		*text;
	struct berval		val, *bv[2] = { &val, NULL };

	/*
	 * database monitor can be defined once only
	 */
	static int 		monitor_defined = 0;

	if ( monitor_defined ) {
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
	monitor_defined++;

	ndn = ch_strdup( SLAPD_MONITOR_DN );
	charray_add( &be->be_suffix, ndn );
	dn_normalize( ndn );
	ber_bvecadd( &be->be_nsuffix, ber_bvstr( ndn ) );

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
		int len = strlen( monitor_subsys[ i ].mss_name );

		monitor_subsys[ i ].mss_rdn = ch_calloc( sizeof( char ), 
				4 + len );
		strcpy( monitor_subsys[ i ].mss_rdn, "cn=" );
		strcat( monitor_subsys[ i ].mss_rdn, 
				monitor_subsys[ i ].mss_name );

		monitor_subsys[ i ].mss_dn = ch_calloc( sizeof( char ), 
				4 + len + sizeof( SLAPD_MONITOR_DN ) );
		strcpy( monitor_subsys[ i ].mss_dn, 
				monitor_subsys[ i ].mss_rdn );
		strcat( monitor_subsys[ i ].mss_dn, "," );
		strcat( monitor_subsys[ i ].mss_dn, SLAPD_MONITOR_DN );

		monitor_subsys[ i ].mss_ndn 
			= ch_strdup( monitor_subsys[ i ].mss_dn );
		dn_normalize( monitor_subsys[ i ].mss_ndn );

		snprintf( buf, sizeof( buf ),
				"dn: %s\n"
				"objectClass: top\n"
				"objectClass: LDAPsubEntry\n"
#ifdef SLAPD_MONITORSUBENTRY
				"objectClass: monitorSubEntry\n"
#else /* !SLAPD_MONITORSUBENTRY */
				"objectClass: extensibleObject\n"
#endif /* !SLAPD_MONITORSUBENTRY */
				"cn: %s\n",
				monitor_subsys[ i ].mss_dn,
				monitor_subsys[ i ].mss_name );
		
		e = str2entry( buf );
		
		if ( e == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"unable to create '%s' entry\n", 
				monitor_subsys[ i ].mss_dn ));
#else
			Debug( LDAP_DEBUG_ANY,
				"unable to create '%s' entry\n%s%s", 
				monitor_subsys[ i ].mss_dn, "", "" );
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
				monitor_subsys[ i ].mss_dn ));
#else
			Debug( LDAP_DEBUG_ANY,
				"unable to add entry '%s' to cache\n%s%s",
				monitor_subsys[ i ].mss_dn, "", "" );
#endif
			return -1;
		}

		e_tmp = e;
	}

	/*
	 * creates the "cn=Monitor" entry 
	 */
	snprintf( buf, sizeof( buf ), 
			"dn: %s\n"
			"objectClass: top\n"
			"objectClass: LDAPsubEntry\n"
#ifdef SLAPD_MONITORSUBENTRY
			"objectClass: monitorSubEntry\n"
#else /* !SLAPD_MONITORSUBENTRY */
			"objectClass: extensibleObject\n"
#endif /* !SLAPD_MONITORSUBENTRY */
			"cn: Monitor",
			SLAPD_MONITOR_DN
			);
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
	val.bv_val = (char *) Versionstr;
	end_of_line = strchr( Versionstr, '\n' );
	if ( end_of_line ) {
		val.bv_len = end_of_line - Versionstr;
	} else {
		val.bv_len = strlen( Versionstr );
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
	char			*ndn;

	/*
	 * adds the monitor backend
	 */
	ndn = ch_strdup( SLAPD_MONITOR_DN );
	dn_normalize( ndn );
	be = select_backend( ndn , 0, 0 );
	ch_free( ndn );
	if ( be == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"unable to get monitor backend\n" ));
#else
		Debug( LDAP_DEBUG_ANY,
			"unable to get monitor backend\n%s%s%s", "", "", "" );
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


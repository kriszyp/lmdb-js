/* init.c - initialize monitor backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include <lutil.h>
#include "slap.h"
#include "lber_pvt.h"
#include "back-monitor.h"

#undef INTEGRATE_CORE_SCHEMA

/*
 * used by many functions to add description to entries
 */
BackendDB *be_monitor = NULL;

static struct monitor_subsys_t	**monitor_subsys = NULL;
static int			monitor_subsys_opened = 0;

/*
 * subsystem data
 *
 * the known subsystems are added to the subsystems
 * array at backend initialization; other subsystems
 * may be added by calling monitor_back_register_subsys()
 * before the database is opened (e.g. by other backends
 * or by overlays or modules).
 */
static struct monitor_subsys_t known_monitor_subsys[] = {
	{ 
		SLAPD_MONITOR_BACKEND_NAME, 
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_backend_init,
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_CONN_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_VOLATILE_CH,
		monitor_subsys_conn_init,
		monitor_subsys_conn_update,
		monitor_subsys_conn_create,
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_DATABASE_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_database_init,
		NULL,   /* update */
		NULL,   /* create */
		monitor_subsys_database_modify
       	}, { 
		SLAPD_MONITOR_LISTENER_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_listener_init,
		NULL,	/* update */
		NULL,	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_LOG_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_NONE,
		monitor_subsys_log_init,
		NULL,	/* update */
		NULL,   /* create */
		monitor_subsys_log_modify
       	}, { 
		SLAPD_MONITOR_OPS_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_ops_init,
		monitor_subsys_ops_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_OVERLAY_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_overlay_init,
		NULL,	/* update */
		NULL,   /* create */
		NULL,	/* modify */
	}, { 
		SLAPD_MONITOR_SASL_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_SENT_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_sent_init,
		monitor_subsys_sent_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_THREAD_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_thread_init,
		monitor_subsys_thread_update,
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_TIME_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_time_init,
		monitor_subsys_time_update,
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_TLS_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_RWW_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_rww_init,
		monitor_subsys_rww_update,
		NULL, 	/* create */
		NULL	/* modify */
       	}, { NULL }
};

#if SLAPD_MONITOR == SLAPD_MOD_DYNAMIC

int
init_module( int argc, char *argv[] )
{
	BackendInfo bi;

	memset( &bi, '\0', sizeof(bi) );
	bi.bi_type = "monitor";
	bi.bi_init = monitor_back_initialize;
	backend_add( &bi );
	return 0;
}

#endif /* SLAPD_MONITOR */

int
monitor_back_register_subsys( monitor_subsys_t *ms )
{
	int	i = 0;

	if ( monitor_subsys ) {
		for ( ; monitor_subsys[ i ] != NULL; i++ )
			/* just count'em */ ;
	}

	monitor_subsys = ch_realloc( monitor_subsys,
			( 2 + i ) * sizeof( monitor_subsys_t * ) );

	if ( monitor_subsys == NULL ) {
		return -1;
	}

	monitor_subsys[ i ] = ms;
	monitor_subsys[ i + 1 ] = NULL;

	/* if a subsystem is registered __AFTER__ subsystem 
	 * initialization (depending on the sequence the databases
	 * are listed in slapd.conf), init it */
	if ( monitor_subsys_opened ) {

		/* FIXME: this should only be possible
		 * if be_monitor is already initialized */
		assert( be_monitor );

		if ( ms->mss_open && ( *ms->mss_open )( be_monitor, ms ) ) {
			return -1;
		}

		ms->mss_flags |= MONITOR_F_OPENED;
	}

	return 0;
}

typedef struct entry_limbo_t {
	struct berval		el_ndn;
	Entry			*el_e;
	monitor_callback_t	*el_cb;
	void			*el_private;
	struct entry_limbo_t	*el_next;
} entry_limbo_t;

int
monitor_back_register_entry(
		Entry			*e,
		monitor_callback_t	*cb,
		void			*private )
{
	monitor_info_t 	*mi = ( monitor_info_t * )be_monitor->be_private;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private == NULL );
	
	if ( monitor_subsys_opened ) {
		Entry			*e2 = NULL,
					**ep = NULL;
		struct berval		pdn = BER_BVNULL;
		monitor_entry_t *mp = NULL,
					*pmp = NULL;

		if ( monitor_cache_get( mi, &e->e_nname, &e2 ) == 0 ) {
			/* entry exists */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry exists\n",
				e->e_name.bv_val, 0, 0 );
			monitor_cache_release( mi, e2 );
			return -1;
		}

		dnParent( &e->e_nname, &pdn );
		if ( monitor_cache_get( mi, &pdn, &e2 ) != 0 ) {
			/* parent does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"parent \"%s\" not found\n",
				e->e_name.bv_val, pdn.bv_val, 0 );
			return -1;
		}

		assert( e2->e_private != NULL );
		pmp = ( monitor_entry_t * )e2->e_private;

		if ( pmp->mp_flags & MONITOR_F_VOLATILE ) {
			/* entry is volatile; cannot append children */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"parent \"%s\" is volatile\n",
				e->e_name.bv_val, e2->e_name.bv_val, 0 );
			monitor_cache_release( mi, e2 );
			return -1;
		}

		mp = monitor_entrypriv_create();
		if ( mp == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"monitor_entrypriv_create failed\n",
				e->e_name.bv_val, 0, 0 );
			return -1;
		}
		e->e_private = ( void * )mp;
		mp->mp_info = pmp->mp_info;
		mp->mp_flags = pmp->mp_flags | MONITOR_F_SUB;

		ep = &pmp->mp_children;
		for ( ; *ep; ) {
			pmp = ( monitor_entry_t * )(*ep)->e_private;
			ep = &pmp->mp_next;
		}
		*ep = e;

		if ( monitor_cache_add( mi, e ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"unable to add entry\n",
				e->e_name.bv_val, 0, 0 );
			ch_free( e->e_private );
			e->e_private = NULL;
			return( -1 );
		}

	} else {
		entry_limbo_t		*el;

		el = (entry_limbo_t *)ch_malloc( sizeof( entry_limbo_t ) );

		BER_BVZERO( &el->el_ndn );
		el->el_e = e;
		el->el_cb = cb;
		el->el_private = private;
		el->el_next = (entry_limbo_t *)mi->mi_entry_limbo;
	}

	return 0;
}

int
monitor_back_register_entry_callback(
		struct berval		*ndn,
		struct monitor_callback_t	*cb,
		void			*private )
{
	monitor_info_t 	*mi = ( monitor_info_t * )be_monitor->be_private;

	assert( mi != NULL );
	assert( ndn != NULL );
	assert( !BER_BVISNULL( ndn ) );
	
	if ( monitor_subsys_opened ) {
		Entry			*e = NULL;
		monitor_entry_t *mp = NULL;
		struct monitor_callback_t	**mcp = NULL;

		if ( monitor_cache_get( mi, ndn, &e ) != 0 ) {
			/* entry does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_callback(\"%s\"): "
				"entry does not exist\n",
				e->e_name.bv_val, 0, 0 );
			return -1;
		}

		assert( e->e_private != NULL );
		mp = ( monitor_entry_t * )e->e_private;

		if ( mp->mp_flags & MONITOR_F_VOLATILE ) {
			/* entry is volatile; cannot append callback */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_callback(\"%s\"): "
				"entry is volatile\n",
				e->e_name.bv_val, 0, 0 );
			monitor_cache_release( mi, e );
			return -1;
		}

		for ( mcp = &mp->mp_cb; *mcp; mcp = &(*mcp)->mc_next )
			/* go to tail */ ;
		
		/* NOTE: we do not clear cb->mc_next, so this function
		 * can be used to append a list of callbacks */
		(*mcp) = cb;

		monitor_cache_release( mi, e );

	} else {
		entry_limbo_t		*el;

		el = (entry_limbo_t *)ch_malloc( sizeof( entry_limbo_t ) );

		ber_dupbv( &el->el_ndn, ndn );
		el->el_e = NULL;
		el->el_cb = cb;
		el->el_private = private;
		el->el_next = (entry_limbo_t *)mi->mi_entry_limbo;
	}

	return 0;
}

monitor_subsys_t *
monitor_back_get_subsys( const char *name )
{
	if ( monitor_subsys != NULL ) {
		int	i;
		
		for ( i = 0; monitor_subsys[ i ] != NULL; i++ ) {
			if ( strcasecmp( monitor_subsys[ i ]->mss_name, name ) == 0 ) {
				return monitor_subsys[ i ];
			}
		}
	}

	return NULL;
}

monitor_subsys_t *
monitor_back_get_subsys_by_dn( struct berval *ndn, int sub )
{
	if ( monitor_subsys != NULL ) {
		int	i;

		if ( sub ) {
			for ( i = 0; monitor_subsys[ i ] != NULL; i++ ) {
				if ( dnIsSuffix( ndn, &monitor_subsys[ i ]->mss_ndn ) ) {
					return monitor_subsys[ i ];
				}
			}

		} else {
			for ( i = 0; monitor_subsys[ i ] != NULL; i++ ) {
				if ( dn_match( ndn, &monitor_subsys[ i ]->mss_ndn ) ) {
					return monitor_subsys[ i ];
				}
			}
		}
	}

	return NULL;
}

int
monitor_back_initialize(
	BackendInfo	*bi
)
{
	monitor_subsys_t	*ms;
	static char		*controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		LDAP_CONTROL_VALUESRETURNFILTER,
		NULL
	};

	bi->bi_controls = controls;

	bi->bi_init = 0;
	bi->bi_open = 0;
	bi->bi_config = monitor_back_config;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = monitor_back_db_init;
	bi->bi_db_config = monitor_back_db_config;
	bi->bi_db_open = monitor_back_db_open;
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
	bi->bi_tool_dn2id_get = 0;
	bi->bi_tool_id2entry_get = 0;
	bi->bi_tool_entry_modify = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	for ( ms = known_monitor_subsys; ms->mss_name != NULL; ms++ ) {
		if ( monitor_back_register_subsys( ms ) ) {
			return -1;
		}
	}

	return 0;
}

int
monitor_back_db_init(
	BackendDB	*be
)
{
	monitor_info_t 	*mi;
	int		i, rc;
	struct berval	dn, ndn;
	struct berval	bv;
	const char	*text;

	struct m_s {
		char	*name;
		char	*schema;
		slap_mask_t flags;
		int	offset;
	} moc[] = {
		{ "monitor", "( 1.3.6.1.4.1.4203.666.3.2 "
			"NAME 'monitor' "
			"DESC 'OpenLDAP system monitoring' "
			"SUP top STRUCTURAL "
			"MUST cn "
			"MAY ( "
				"description "
				"$ l "
#if 0	/* temporarily disabled */
				"$ st "
				"$ street "
				"$ postalAddress "
				"$ postalCode "
#endif
				"$ seeAlso "
				"$ labeledURI "
				"$ monitoredInfo "
				"$ managedInfo "
				"$ monitorOverlay "
			") )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitor) },
		{ "monitorServer", "( 1.3.6.1.4.1.4203.666.3.7 "
			"NAME 'monitorServer' "
			"DESC 'Server monitoring root entry' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorServer) },
		{ "monitorContainer", "( 1.3.6.1.4.1.4203.666.3.8 "
			"NAME 'monitorContainer' "
			"DESC 'monitor container class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorContainer) },
		{ "monitorCounterObject", "( 1.3.6.1.4.1.4203.666.3.9 "
			"NAME 'monitorCounterObject' "
			"DESC 'monitor counter class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorCounterObject) },
		{ "monitorOperation", "( 1.3.6.1.4.1.4203.666.3.10 "
			"NAME 'monitorOperation' "
			"DESC 'monitor operation class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorOperation) },
		{ "monitorConnection", "( 1.3.6.1.4.1.4203.666.3.11 "
			"NAME 'monitorConnection' "
			"DESC 'monitor connection class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorConnection) },
		{ "managedObject", "( 1.3.6.1.4.1.4203.666.3.12 "
			"NAME 'managedObject' "
			"DESC 'monitor managed entity class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_managedObject) },
		{ "monitoredObject", "( 1.3.6.1.4.1.4203.666.3.13 "
			"NAME 'monitoredObject' "
			"DESC 'monitor monitored entity class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitoredObject) },
		{ NULL, NULL, 0, -1 }
	}, mat[] = {
		{ "monitoredInfo", "( 1.3.6.1.4.1.4203.666.1.14 "
			"NAME 'monitoredInfo' "
			"DESC 'monitored info' "
			/* "SUP name " */
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitoredInfo) },
		{ "managedInfo", "( 1.3.6.1.4.1.4203.666.1.15 "
			"NAME 'managedInfo' "
			"DESC 'monitor managed info' "
			"SUP name )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_managedInfo) },
		{ "monitorCounter", "( 1.3.6.1.4.1.4203.666.1.16 "
			"NAME 'monitorCounter' "
			"DESC 'monitor counter' "
			"EQUALITY integerMatch "
			"ORDERING integerOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorCounter) },
		{ "monitorOpCompleted", "( 1.3.6.1.4.1.4203.666.1.17 "
			"NAME 'monitorOpCompleted' "
			"DESC 'monitor completed operations' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOpCompleted) },
		{ "monitorOpInitiated", "( 1.3.6.1.4.1.4203.666.1.18 "
			"NAME 'monitorOpInitiated' "
			"DESC 'monitor initiated operations' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOpInitiated) },
		{ "monitorConnectionNumber", "( 1.3.6.1.4.1.4203.666.1.19 "
			"NAME 'monitorConnectionNumber' "
			"DESC 'monitor connection number' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionNumber) },
		{ "monitorConnectionAuthzDN", "( 1.3.6.1.4.1.4203.666.1.20 "
			"NAME 'monitorConnectionAuthzDN' "
			"DESC 'monitor connection authorization DN' "
			/* "SUP distinguishedName " */
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionAuthzDN) },
		{ "monitorConnectionLocalAddress", "( 1.3.6.1.4.1.4203.666.1.21 "
			"NAME 'monitorConnectionLocalAddress' "
			"DESC 'monitor connection local address' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionLocalAddress) },
		{ "monitorConnectionPeerAddress", "( 1.3.6.1.4.1.4203.666.1.22 "
			"NAME 'monitorConnectionPeerAddress' "
			"DESC 'monitor connection peer address' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionPeerAddress) },
		{ "monitorTimestamp", "( 1.3.6.1.4.1.4203.666.1.24 "
			"NAME 'monitorTimestamp' "
			"DESC 'monitor timestamp' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
			"SINGLE-VALUE "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorTimestamp) },
		{ "monitorOverlay", "( 1.3.6.1.4.1.4203.666.1.27 "
			"NAME 'monitorOverlay' "
			"DESC 'name of overlays defined for a give database' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOverlay) },
		{ "readOnly", "( 1.3.6.1.4.1.4203.666.1.31 "
			"NAME 'readOnly' "
			"DESC 'read/write status of a given database' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_readOnly) },
		{ "restrictedOperation", "( 1.3.6.1.4.1.4203.666.1.32 "
			"NAME 'restrictedOperation' "
			"DESC 'name of restricted operation for a given database' "
			"SUP managedInfo )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_restrictedOperation ) },
#ifdef INTEGRATE_CORE_SCHEMA
		{ NULL, NULL, 0, -1 },	/* description */
		{ NULL, NULL, 0, -1 },	/* seeAlso */
		{ NULL, NULL, 0, -1 },	/* l */
		{ NULL, NULL, 0, -1 },	/* labeledURI */
#endif /* INTEGRATE_CORE_SCHEMA */
		{ NULL, NULL, 0, -1 }
	}, mat_core[] = {
		{ "description", "( 2.5.4.13 "
			"NAME 'description' "
			"DESC 'RFC2256: descriptive information' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )", 0,
			offsetof(monitor_info_t, mi_ad_description) },
		{ "seeAlso", "( 2.5.4.34 "
			"NAME 'seeAlso' "
			"DESC 'RFC2256: DN of related object' "
			"SUP distinguishedName )", 0,
			offsetof(monitor_info_t, mi_ad_seeAlso) },
		{ "l", "( 2.5.4.7 "
			"NAME ( 'l' 'localityName' ) "
			"DESC 'RFC2256: locality which this object resides in' "
			"SUP name )", 0,
			offsetof(monitor_info_t, mi_ad_l) },
		{ "labeledURI", "( 1.3.6.1.4.1.250.1.57 "
			"NAME 'labeledURI' "
			"DESC 'RFC2079: Uniform Resource Identifier with optional label' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", 0,
			offsetof(monitor_info_t, mi_ad_labeledURI) },
		{ NULL, NULL, 0, -1 }
	};
	
	/*
	 * database monitor can be defined once only
	 */
	if ( be_monitor ) {
		Debug( LDAP_DEBUG_ANY,
			"only one monitor backend is allowed\n", 0, 0, 0 );
		return( -1 );
	}
	be_monitor = be;

	/* indicate system schema supported */
	SLAP_BFLAGS(be) |= SLAP_BFLAG_MONITOR;

	dn.bv_val = SLAPD_MONITOR_DN;
	dn.bv_len = sizeof( SLAPD_MONITOR_DN ) - 1;

	rc = dnNormalize( 0, NULL, NULL, &dn, &ndn, NULL );
	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"unable to normalize monitor DN \"%s\"\n",
			SLAPD_MONITOR_DN, 0, 0 );
		return -1;
	}

	ber_dupbv( &bv, &dn );
	ber_bvarray_add( &be->be_suffix, &bv );
	ber_bvarray_add( &be->be_nsuffix, &ndn );

	mi = ( monitor_info_t * )ch_calloc( sizeof( monitor_info_t ), 1 );
	if ( mi == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"unable to initialize monitor backend\n", 0, 0, 0 );
		return -1;
	}

	memset( mi, 0, sizeof( monitor_info_t ) );

	ldap_pvt_thread_mutex_init( &mi->mi_cache_mutex );

	be->be_private = mi;
	
#ifdef INTEGRATE_CORE_SCHEMA
	/* prepare for schema integration */
	for ( k = 0; mat[ k ].name != NULL; k++ );
#endif /* INTEGRATE_CORE_SCHEMA */

	for ( i = 0; mat_core[ i ].name != NULL; i++ ) {
		AttributeDescription	**ad;
		const char		*text;

		ad = ((AttributeDescription **)&(((char *)mi)[ mat_core[ i ].offset ]));
		ad[ 0 ] = NULL;

		switch (slap_str2ad( mat_core[ i ].name, ad, &text ) ) {
		case LDAP_SUCCESS:
			break;

#ifdef INTEGRATE_CORE_SCHEMA
		case LDAP_UNDEFINED_TYPE:
			mat[ k ] = mat_core[ i ];
			k++;
			break;
#endif /* INTEGRATE_CORE_SCHEMA */

		default:
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_db_init: %s: %s\n",
				mat_core[ i ].name, text, 0 );
			return( -1 );
		}
	}

	/* schema integration */
	for ( i = 0; mat[ i ].name; i++ ) {
		LDAPAttributeType	*at;
		int			code;
		const char		*err;
		AttributeDescription	**ad;

		at = ldap_str2attributetype( mat[ i ].schema, &code,
			&err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !at ) {
			Debug( LDAP_DEBUG_ANY, "monitor_back_db_init: "
				"in AttributeType \"%s\" %s before %s\n",
				mat[ i ].name, ldap_scherr2str(code), err );
			return -1;
		}

		if ( at->at_oid == NULL ) {
			Debug( LDAP_DEBUG_ANY, "monitor_back_db_init: "
				"null OID for attributeType \"%s\"\n",
				mat[ i ].name, 0, 0 );
			return -1;
		}

		code = at_add(at, &err);
		if ( code ) {
			Debug( LDAP_DEBUG_ANY, "monitor_back_db_init: "
				"%s in attributeType \"%s\"\n",
				scherr2str(code), mat[ i ].name, 0 );
			return -1;
		}
		ldap_memfree(at);

		ad = ((AttributeDescription **)&(((char *)mi)[ mat[ i ].offset ]));
		ad[ 0 ] = NULL;
		if ( slap_str2ad( mat[ i ].name, ad, &text ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_db_init: %s\n", text, 0, 0 );
			return -1;
		}

		(*ad)->ad_type->sat_flags |= mat[ i ].flags;
	}

	for ( i = 0; moc[ i ].name; i++ ) {
		LDAPObjectClass		*oc;
		int			code;
		const char		*err;
		ObjectClass		*Oc;

		oc = ldap_str2objectclass(moc[ i ].schema, &code, &err,
				LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			Debug( LDAP_DEBUG_ANY,
				"unable to parse monitor objectclass \"%s\": "
				"%s before %s\n" , moc[ i ].name,
				ldap_scherr2str(code), err );
			return -1;
		}

		if ( oc->oc_oid == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"objectclass \"%s\" has no OID\n" ,
				moc[ i ].name, 0, 0 );
			return -1;
		}

		code = oc_add(oc, 0, &err);
		if ( code ) {
			Debug( LDAP_DEBUG_ANY,
				"objectclass \"%s\": %s \"%s\"\n" ,
				moc[ i ].name, scherr2str(code), err );
			return -1;
		}

		ldap_memfree(oc);

		Oc = oc_find( moc[ i ].name );
		if ( Oc == NULL ) {
			Debug( LDAP_DEBUG_ANY, "monitor_back_db_init: "
					"unable to find objectClass %s "
					"(just added)\n", moc[ i ].name, 0, 0 );
			return -1;
		}

		Oc->soc_flags |= moc[ i ].flags;

		((ObjectClass **)&(((char *)mi)[ moc[ i ].offset ]))[ 0 ] = Oc;
	}

	return 0;
}

int
monitor_back_db_open(
	BackendDB	*be
)
{
	monitor_info_t 		*mi = (monitor_info_t *)be->be_private;
	struct monitor_subsys_t	**ms;
	Entry 			*e, **ep;
	monitor_entry_t		*mp;
	int			i;
	char 			buf[ BACKMONITOR_BUFSIZE ],
				*end_of_line;
	struct berval		bv;
	struct tm		*tms;
#ifdef HAVE_GMTIME_R
	struct tm		tm_buf;
#endif
	static char		tmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];

	/*
	 * Start
	 */
#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#endif
#ifdef HACK_LOCAL_TIME
# ifdef HAVE_LOCALTIME_R
	tms = localtime_r( &starttime, &tm_buf );
# else
	tms = localtime( &starttime );
# endif /* HAVE_LOCALTIME_R */
	lutil_localtime( tmbuf, sizeof(tmbuf), tms, -timezone );
#else /* !HACK_LOCAL_TIME */
# ifdef HAVE_GMTIME_R
	tms = gmtime_r( &starttime, &tm_buf );
# else
	tms = gmtime( &starttime );
# endif /* HAVE_GMTIME_R */
	lutil_gentime( tmbuf, sizeof(tmbuf), tms );
#endif /* !HACK_LOCAL_TIME */
#ifndef HAVE_GMTIME_R
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif

	mi->mi_startTime.bv_val = tmbuf;
	mi->mi_startTime.bv_len = strlen( tmbuf );

	if ( BER_BVISEMPTY( &be->be_rootdn ) ) {
		BER_BVSTR( &mi->mi_creatorsName, SLAPD_ANONYMOUS );
	} else {
		mi->mi_creatorsName = be->be_rootdn;
	}

	/*
	 * creates the "cn=Monitor" entry 
	 */
	snprintf( buf, sizeof( buf ), 
		"dn: %s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Monitor\n"
		"%s: This subtree contains monitoring/managing objects.\n"
		"%s: This object contains information about this server.\n"
#if 0
		"%s: createTimestamp reflects the time this server instance was created.\n"
		"%s: modifyTimestamp reflects the time this server instance was last accessed.\n"
#endif
		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		SLAPD_MONITOR_DN,
		mi->mi_oc_monitorServer->soc_cname.bv_val,
		mi->mi_oc_monitorServer->soc_cname.bv_val,
		mi->mi_ad_description->ad_cname.bv_val,
		mi->mi_ad_description->ad_cname.bv_val,
#if 0
		mi->mi_ad_description->ad_cname.bv_val,
		mi->mi_ad_description->ad_cname.bv_val,
#endif
		mi->mi_creatorsName.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );

	e = str2entry( buf );
	if ( e == NULL) {
		Debug( LDAP_DEBUG_ANY,
			"unable to create \"%s\" entry\n",
			SLAPD_MONITOR_DN, 0, 0 );
		return( -1 );
	}

	bv.bv_val = (char *) Versionstr;
	end_of_line = strchr( Versionstr, '\n' );
	if ( end_of_line ) {
		bv.bv_len = end_of_line - Versionstr;
	} else {
		bv.bv_len = strlen( Versionstr );
	}

	if ( attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
				&bv, NULL ) ) {
		Debug( LDAP_DEBUG_ANY,
			"unable to add monitoredInfo to \"%s\" entry\n",
			SLAPD_MONITOR_DN, 0, 0 );
		return( -1 );
	}

	if ( mi->mi_l.bv_len ) {
		if ( attr_merge_normalize_one( e, mi->mi_ad_l, &mi->mi_l, NULL ) ) {
			Debug( LDAP_DEBUG_ANY,
				"unable to add locality to \"%s\" entry\n",
				SLAPD_MONITOR_DN, 0, 0 );
			return( -1 );
		}
	}

	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return -1;
	}
	e->e_private = ( void * )mp;
	ep = &mp->mp_children;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"unable to add entry \"%s\" to cache\n",
			SLAPD_MONITOR_DN, 0, 0 );
		return -1;
	}

	/*	
	 * Create all the subsystem specific entries
	 */
	for ( i = 0; monitor_subsys[ i ] != NULL; i++ ) {
		int 		len = strlen( monitor_subsys[ i ]->mss_name );
		struct berval	dn;
		int		rc;

		dn.bv_len = len + sizeof( "cn=" ) - 1;
		dn.bv_val = ch_calloc( sizeof( char ), dn.bv_len + 1 );
		strcpy( dn.bv_val, "cn=" );
		strcat( dn.bv_val, monitor_subsys[ i ]->mss_name );
		rc = dnPretty( NULL, &dn, &monitor_subsys[ i ]->mss_rdn, NULL );
		free( dn.bv_val );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor RDN \"%s\" is invalid\n", 
				dn.bv_val, 0, 0 );
			return( -1 );
		}

		dn.bv_len += sizeof( SLAPD_MONITOR_DN ); /* 1 for the , */
		dn.bv_val = ch_malloc( dn.bv_len + 1 );
		strcpy( dn.bv_val , monitor_subsys[ i ]->mss_rdn.bv_val );
		strcat( dn.bv_val, "," SLAPD_MONITOR_DN );
		rc = dnPrettyNormal( NULL, &dn, &monitor_subsys[ i ]->mss_dn,
			&monitor_subsys[ i ]->mss_ndn, NULL );
		free( dn.bv_val );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor DN \"%s\" is invalid\n", 
				dn.bv_val, 0, 0 );
			return( -1 );
		}

		snprintf( buf, sizeof( buf ),
				"dn: %s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: %s\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				monitor_subsys[ i ]->mss_dn.bv_val,
				mi->mi_oc_monitorContainer->soc_cname.bv_val,
				mi->mi_oc_monitorContainer->soc_cname.bv_val,
				monitor_subsys[ i ]->mss_name,
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		
		if ( e == NULL) {
			Debug( LDAP_DEBUG_ANY,
				"unable to create \"%s\" entry\n", 
				monitor_subsys[ i ]->mss_dn.bv_val, 0, 0 );
			return( -1 );
		}

		mp = monitor_entrypriv_create();
		if ( mp == NULL ) {
			return -1;
		}
		e->e_private = ( void * )mp;
		mp->mp_info = monitor_subsys[ i ];
		mp->mp_flags = monitor_subsys[ i ]->mss_flags;

		if ( monitor_cache_add( mi, e ) ) {
			Debug( LDAP_DEBUG_ANY,
				"unable to add entry \"%s\" to cache\n",
				monitor_subsys[ i ]->mss_dn.bv_val, 0, 0 );
			return -1;
		}

		*ep = e;
		ep = &mp->mp_next;
	}

	assert( be );

	be->be_private = mi;
	
	/*
	 * opens the monitor backend subsystems
	 */
	for ( ms = monitor_subsys; ms[ 0 ] != NULL; ms++ ) {
		if ( ms[ 0 ]->mss_open && ( *ms[ 0 ]->mss_open )( be, ms[ 0 ] ) )
		{
			return( -1 );
		}
		ms[ 0 ]->mss_flags |= MONITOR_F_OPENED;
	}

	monitor_subsys_opened = 1;

	if ( mi->mi_entry_limbo ) {
		entry_limbo_t	*el = (entry_limbo_t *)mi->mi_entry_limbo;

		for ( ; el; ) {
			entry_limbo_t	*tmp;

			if ( el->el_e ) {
				monitor_back_register_entry( el->el_e, el->el_cb, el->el_private );

			} else if ( !BER_BVISNULL( &el->el_ndn ) ) {
				monitor_back_register_entry_callback( &el->el_ndn, el->el_cb, el->el_private );
				ber_memfree( el->el_ndn.bv_val );
			}

			tmp = el;
			el = el->el_next;
			ch_free( tmp );
		}

		mi->mi_entry_limbo = NULL;
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
	return SLAP_CONF_UNKNOWN;
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
	monitor_info_t	*mi = ( monitor_info_t * )be->be_private;

	/*
	 * eventually, will hold database specific configuration parameters
	 */
	if ( strcasecmp( argv[ 0 ], "l" ) == 0 ) {
		if ( argc != 2 ) {
			return 1;
		}
		
		ber_str2bv( argv[ 1 ], 0, 1, &mi->mi_l );

	} else {
		return SLAP_CONF_UNKNOWN;
	}

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


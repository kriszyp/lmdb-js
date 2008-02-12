/* init.c - initialize monitor backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2008 The OpenLDAP Foundation.
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
#include "config.h"
#include "lber_pvt.h"
#include "back-monitor.h"

#undef INTEGRATE_CORE_SCHEMA

/*
 * used by many functions to add description to entries
 *
 * WARNING: be_monitor may change as new databases are added,
 * so it should not be used outside monitor_back_db_init()
 * until monitor_back_db_open is called.
 */
BackendDB			*be_monitor;

static struct monitor_subsys_t	**monitor_subsys;
static int			monitor_subsys_opened;
static monitor_info_t		monitor_info;

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
		{ BER_BVC( "This subsystem contains information about available backends." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_backend_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_CONN_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about connections." ),
			BER_BVNULL },
		MONITOR_F_VOLATILE_CH,
		monitor_subsys_conn_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_DATABASE_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about configured databases." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_database_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_LISTENER_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about active listeners." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_listener_init,
		NULL,	/* destroy */
		NULL,	/* update */
		NULL,	/* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_LOG_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about logging." ),
		  	BER_BVC( "Set the attribute \"managedInfo\" to the desired log levels." ),
			BER_BVNULL },
		MONITOR_F_NONE,
		monitor_subsys_log_init,
		NULL,	/* destroy */
		NULL,	/* update */
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_OPS_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about performed operations." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_ops_init,
		NULL,	/* destroy */
		NULL,	/* update */
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_OVERLAY_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about available overlays." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_overlay_init,
		NULL,	/* destroy */
		NULL,	/* update */
		NULL,   /* create */
		NULL,	/* modify */
	}, { 
		SLAPD_MONITOR_SASL_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about SASL." ),
			BER_BVNULL },
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_SENT_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains statistics." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_sent_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_THREAD_NAME, 	
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about threads." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_thread_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_TIME_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about time." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_time_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL,	/* modify */
       	}, { 
		SLAPD_MONITOR_TLS_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about TLS." ),
			BER_BVNULL },
		MONITOR_F_NONE,
		NULL,   /* init */
		NULL,	/* destroy */
		NULL,   /* update */
		NULL,   /* create */
		NULL	/* modify */
       	}, { 
		SLAPD_MONITOR_RWW_NAME,
		BER_BVNULL, BER_BVNULL, BER_BVNULL,
		{ BER_BVC( "This subsystem contains information about read/write waiters." ),
			BER_BVNULL },
		MONITOR_F_PERSISTENT_CH,
		monitor_subsys_rww_init,
		NULL,	/* destroy */
		NULL,   /* update */
		NULL, 	/* create */
		NULL	/* modify */
       	}, { NULL }
};

int
monitor_back_register_subsys(
	monitor_subsys_t	*ms )
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
		assert( be_monitor != NULL );

		if ( ms->mss_open && ( *ms->mss_open )( be_monitor, ms ) ) {
			return -1;
		}

		ms->mss_flags |= MONITOR_F_OPENED;
	}

	return 0;
}

enum {
	LIMBO_ENTRY,
	LIMBO_ENTRY_PARENT,
	LIMBO_ATTRS,
	LIMBO_CB
};

typedef struct entry_limbo_t {
	int			el_type;
	Entry			*el_e;
	Attribute		*el_a;
	struct berval		el_ndn;
	struct berval		el_base;
	int			el_scope;
	struct berval		el_filter;
	monitor_callback_t	*el_cb;
	struct entry_limbo_t	*el_next;
} entry_limbo_t;

int
monitor_back_is_configured( void )
{
	return be_monitor != NULL;
}

int
monitor_back_register_entry(
	Entry			*e,
	monitor_callback_t	*cb )
{
	monitor_info_t 	*mi;

	if ( be_monitor == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_back_register_entry(\"%s\"): "
			"monitor database not configured.\n",
			e->e_name.bv_val, 0, 0 );
		return -1;
	}

	mi = ( monitor_info_t * )be_monitor->be_private;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private == NULL );
	
	if ( monitor_subsys_opened ) {
		Entry		*e_parent = NULL,
				*e_new = NULL,
				**ep = NULL;
		struct berval	pdn = BER_BVNULL;
		monitor_entry_t *mp = NULL,
				*mp_parent = NULL;
		int		rc = 0;

		if ( monitor_cache_get( mi, &e->e_nname, &e_parent ) == 0 ) {
			/* entry exists */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry exists\n",
				e->e_name.bv_val, 0, 0 );
			monitor_cache_release( mi, e_parent );
			return -1;
		}

		dnParent( &e->e_nname, &pdn );
		if ( monitor_cache_get( mi, &pdn, &e_parent ) != 0 ) {
			/* parent does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"parent \"%s\" not found\n",
				e->e_name.bv_val, pdn.bv_val, 0 );
			return -1;
		}

		assert( e_parent->e_private != NULL );
		mp_parent = ( monitor_entry_t * )e_parent->e_private;

		if ( mp_parent->mp_flags & MONITOR_F_VOLATILE ) {
			/* entry is volatile; cannot append children */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"parent \"%s\" is volatile\n",
				e->e_name.bv_val, e_parent->e_name.bv_val, 0 );
			rc = -1;
			goto done;
		}

		mp = monitor_entrypriv_create();
		if ( mp == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"monitor_entrypriv_create() failed\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

		e_new = entry_dup( e );
		if ( e_new == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry_dup() failed\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}
		
		e_new->e_private = ( void * )mp;
		mp->mp_info = mp_parent->mp_info;
		mp->mp_flags = mp_parent->mp_flags | MONITOR_F_SUB;
		mp->mp_cb = cb;

		ep = &mp_parent->mp_children;
		for ( ; *ep; ) {
			mp_parent = ( monitor_entry_t * )(*ep)->e_private;
			ep = &mp_parent->mp_next;
		}
		*ep = e_new;

		if ( monitor_cache_add( mi, e_new ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"unable to add entry\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

done:;
		if ( rc ) {
			if ( mp ) {
				ch_free( mp );
			}
			if ( e_new ) {
				e_new->e_private = NULL;
				entry_free( e_new );
			}
		}

		if ( e_parent ) {
			monitor_cache_release( mi, e_parent );
		}

	} else {
		entry_limbo_t	**elpp, el = { 0 };

		el.el_type = LIMBO_ENTRY;

		el.el_e = entry_dup( e );
		if ( el.el_e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry_dup() failed\n",
				e->e_name.bv_val, 0, 0 );
			return -1;
		}
		
		el.el_cb = cb;

		for ( elpp = (entry_limbo_t **)&mi->mi_entry_limbo;
				*elpp;
				elpp = &(*elpp)->el_next )
			/* go to last */;

		*elpp = (entry_limbo_t *)ch_malloc( sizeof( entry_limbo_t ) );
		if ( *elpp == NULL ) {
			el.el_e->e_private = NULL;
			entry_free( el.el_e );
			return -1;
		}

		el.el_next = NULL;
		**elpp = el;
	}

	return 0;
}

int
monitor_back_register_entry_parent(
	Entry			*e,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter )
{
	monitor_info_t 	*mi;
	struct berval	ndn = BER_BVNULL;

	if ( be_monitor == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_back_register_entry_parent(base=\"%s\" scope=%s filter=\"%s\"): "
			"monitor database not configured.\n",
			BER_BVISNULL( base ) ? "" : base->bv_val,
			scope == LDAP_SCOPE_BASE ? "base" : ( scope == LDAP_SCOPE_ONELEVEL ? "one" : "subtree" ),
			BER_BVISNULL( filter ) ? "" : filter->bv_val );
		return -1;
	}

	mi = ( monitor_info_t * )be_monitor->be_private;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private == NULL );

	if ( BER_BVISNULL( filter ) ) {
		/* need a filter */
		Debug( LDAP_DEBUG_ANY,
			"monitor_back_register_entry_parent(\"\"): "
			"need a valid filter\n",
			0, 0, 0 );
		return -1;
	}

	if ( monitor_subsys_opened ) {
		Entry		*e_parent = NULL,
				*e_new = NULL,
				**ep = NULL;
		struct berval	e_name = BER_BVNULL,
				e_nname = BER_BVNULL;
		monitor_entry_t *mp = NULL,
				*mp_parent = NULL;
		int		rc = 0;

		if ( monitor_filter2ndn( base, scope, filter, &ndn ) ) {
			/* entry does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_parent(\"\"): "
				"base=%s scope=%d filter=%s : "
				"unable to find entry\n",
				base->bv_val ? base->bv_val : "\"\"",
				scope, filter->bv_val );
			return -1;
		}

		if ( monitor_cache_get( mi, &ndn, &e_parent ) != 0 ) {
			/* entry does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_parent(\"%s\"): "
				"parent entry does not exist\n",
				ndn.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

		assert( e_parent->e_private != NULL );
		mp_parent = ( monitor_entry_t * )e_parent->e_private;

		if ( mp_parent->mp_flags & MONITOR_F_VOLATILE ) {
			/* entry is volatile; cannot append callback */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_parent(\"%s\"): "
				"entry is volatile\n",
				e_parent->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

		build_new_dn( &e_name, &e_parent->e_name, &e->e_name, NULL );
		build_new_dn( &e_nname, &e_parent->e_nname, &e->e_nname, NULL );

		if ( monitor_cache_get( mi, &e_nname, &e_new ) == 0 ) {
			/* entry already exists */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_parent(\"%s\"): "
				"entry already exists\n",
				e_name.bv_val, 0, 0 );
			monitor_cache_release( mi, e_new );
			rc = -1;
			goto done;
		}

		mp = monitor_entrypriv_create();
		if ( mp == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_parent(\"%s\"): "
				"monitor_entrypriv_create() failed\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

		e_new = entry_dup( e );
		if ( e_new == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry_dup() failed\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}
		ch_free( e_new->e_name.bv_val );
		ch_free( e_new->e_nname.bv_val );
		e_new->e_name = e_name;
		e_new->e_nname = e_nname;
		
		e_new->e_private = ( void * )mp;
		mp->mp_info = mp_parent->mp_info;
		mp->mp_flags = mp_parent->mp_flags | MONITOR_F_SUB;
		mp->mp_cb = cb;

		ep = &mp_parent->mp_children;
		for ( ; *ep; ) {
			mp_parent = ( monitor_entry_t * )(*ep)->e_private;
			ep = &mp_parent->mp_next;
		}
		*ep = e_new;

		if ( monitor_cache_add( mi, e_new ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"unable to add entry\n",
				e->e_name.bv_val, 0, 0 );
			rc = -1;
			goto done;
		}

done:;
		if ( !BER_BVISNULL( &ndn ) ) {
			ch_free( ndn.bv_val );
		}

		if ( rc ) {
			if ( mp ) {
				ch_free( mp );
			}
			if ( e_new ) {
				e_new->e_private = NULL;
				entry_free( e_new );
			}
		}

		if ( e_parent ) {
			monitor_cache_release( mi, e_parent );
		}

	} else {
		entry_limbo_t	**elpp, el = { 0 };

		el.el_type = LIMBO_ENTRY_PARENT;

		el.el_e = entry_dup( e );
		if ( el.el_e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry(\"%s\"): "
				"entry_dup() failed\n",
				e->e_name.bv_val, 0, 0 );
			return -1;
		}
		
		if ( !BER_BVISNULL( base ) ) {
			ber_dupbv( &el.el_base, base );
		}
		el.el_scope = scope;
		if ( !BER_BVISNULL( filter ) ) {
			ber_dupbv( &el.el_filter, filter );
		}

		el.el_cb = cb;

		for ( elpp = (entry_limbo_t **)&mi->mi_entry_limbo;
				*elpp;
				elpp = &(*elpp)->el_next )
			/* go to last */;

		*elpp = (entry_limbo_t *)ch_malloc( sizeof( entry_limbo_t ) );
		if ( *elpp == NULL ) {
			el.el_e->e_private = NULL;
			entry_free( el.el_e );
			return -1;
		}

		el.el_next = NULL;
		**elpp = el;
	}

	return 0;
}

static int
monitor_filter2ndn_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		struct berval	*ndn = op->o_callback->sc_private;
		
		ber_dupbv( ndn, &rs->sr_entry->e_nname );
	}

	return 0;
}

int
monitor_filter2ndn(
	struct berval	*base,
	int		scope,
	struct berval	*filter,
	struct berval	*ndn )
{
	Connection	conn = { 0 };
	OperationBuffer	opbuf;
	Operation	*op;
	void	*thrctx;
	SlapReply	rs = { 0 };
	slap_callback	cb = { NULL, monitor_filter2ndn_cb, NULL, NULL };
	int		rc;

	BER_BVZERO( ndn );

	if ( be_monitor == NULL ) {
		return -1;
	}

	op = (Operation *) &opbuf;
	thrctx = ldap_pvt_thread_pool_context();
	connection_fake_init( &conn, op, thrctx );

	op->o_tag = LDAP_REQ_SEARCH;

	op->o_bd = be_monitor;
	if ( base == NULL || BER_BVISNULL( base ) ) {
		ber_dupbv_x( &op->o_req_dn, &op->o_bd->be_suffix[ 0 ],
				op->o_tmpmemctx );
		ber_dupbv_x( &op->o_req_ndn, &op->o_bd->be_nsuffix[ 0 ],
				op->o_tmpmemctx );

	} else {
		if ( dnPrettyNormal( NULL, base, &op->o_req_dn, &op->o_req_ndn,
					op->o_tmpmemctx ) ) {
			return -1;
		}
	}

	op->o_callback = &cb;
	cb.sc_private = (void *)ndn;

	op->ors_scope = scope;
	ber_dupbv_x( &op->ors_filterstr, filter, op->o_tmpmemctx );
	op->ors_filter = str2filter_x( op, filter->bv_val );
	op->ors_attrs = slap_anlist_no_attrs;
	op->ors_attrsonly = 0;
	op->ors_tlimit = SLAP_NO_LIMIT;
	op->ors_slimit = 1;
	op->ors_limit = NULL;
	op->ors_deref = LDAP_DEREF_NEVER;

	op->o_nocaching = 1;
	op->o_managedsait = SLAP_CONTROL_NONCRITICAL;

	op->o_dn = be_monitor->be_rootdn;
	op->o_ndn = be_monitor->be_rootndn;

	rc = op->o_bd->be_search( op, &rs );

	filter_free_x( op, op->ors_filter );
	op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );

	if ( rc != 0 ) {
		return rc;
	}

	switch ( rs.sr_err ) {
	case LDAP_SUCCESS:
		if ( BER_BVISNULL( ndn ) ) {
			rc = -1;
		}
		break;
			
	case LDAP_SIZELIMIT_EXCEEDED:
	default:
		if ( !BER_BVISNULL( ndn ) ) {
			ber_memfree( ndn->bv_val );
			BER_BVZERO( ndn );
		}
		rc = -1;
		break;
	}

	return rc;
}

int
monitor_back_register_entry_attrs(
	struct berval		*ndn_in,
	Attribute		*a,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter )
{
	monitor_info_t 	*mi;
	struct berval	ndn = BER_BVNULL;
	char		*fname = ( a == NULL ? "callback" : "attrs" );

	if ( be_monitor == NULL ) {
		char		buf[ SLAP_TEXT_BUFLEN ];

		snprintf( buf, sizeof( buf ),
			"monitor_back_register_entry_%s(base=\"%s\" scope=%s filter=\"%s\"): "
			"monitor database not configured.\n",
			fname,
			BER_BVISNULL( base ) ? "" : base->bv_val,
			scope == LDAP_SCOPE_BASE ? "base" : ( scope == LDAP_SCOPE_ONELEVEL ? "one" : "subtree" ),
			BER_BVISNULL( filter ) ? "" : filter->bv_val );
		Debug( LDAP_DEBUG_ANY, "%s\n", buf, 0, 0 );

		return -1;
	}

	mi = ( monitor_info_t * )be_monitor->be_private;

	assert( mi != NULL );

	if ( ndn_in != NULL ) {
		ndn = *ndn_in;
	}

	if ( a == NULL && cb == NULL ) {
		/* nothing to do */
		return -1;
	}

	if ( ( ndn_in == NULL || BER_BVISNULL( &ndn ) )
			&& BER_BVISNULL( filter ) )
	{
		/* need a filter */
		Debug( LDAP_DEBUG_ANY,
			"monitor_back_register_entry_%s(\"\"): "
			"need a valid filter\n",
			fname, 0, 0 );
		return -1;
	}

	if ( monitor_subsys_opened ) {
		Entry			*e = NULL;
		Attribute		**atp = NULL;
		monitor_entry_t 	*mp = NULL;
		monitor_callback_t	**mcp = NULL;
		int			rc = 0;
		int			freeit = 0;

		if ( BER_BVISNULL( &ndn ) ) {
			if ( monitor_filter2ndn( base, scope, filter, &ndn ) ) {
				char		buf[ SLAP_TEXT_BUFLEN ];

				snprintf( buf, sizeof( buf ),
					"monitor_back_register_entry_%s(\"\"): "
					"base=%s scope=%d filter=%s : "
					"unable to find entry\n",
					fname,
					base->bv_val ? base->bv_val : "\"\"",
					scope, filter->bv_val );

				/* entry does not exist */
				Debug( LDAP_DEBUG_ANY, "%s\n", buf, 0, 0 );
				return -1;
			}

			freeit = 1;
		}

		if ( monitor_cache_get( mi, &ndn, &e ) != 0 ) {
			/* entry does not exist */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_%s(\"%s\"): "
				"entry does not exist\n",
				fname, ndn.bv_val, 0 );
			rc = -1;
			goto done;
		}

		assert( e->e_private != NULL );
		mp = ( monitor_entry_t * )e->e_private;

		if ( mp->mp_flags & MONITOR_F_VOLATILE ) {
			/* entry is volatile; cannot append callback */
			Debug( LDAP_DEBUG_ANY,
				"monitor_back_register_entry_%s(\"%s\"): "
				"entry is volatile\n",
				fname, e->e_name.bv_val, 0 );
			rc = -1;
			goto done;
		}

		if ( a ) {
			for ( atp = &e->e_attrs; *atp; atp = &(*atp)->a_next )
				/* just get to last */ ;

			*atp = attrs_dup( a );
			if ( *atp == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"monitor_back_register_entry_%s(\"%s\"): "
					"attrs_dup() failed\n",
					fname, e->e_name.bv_val, 0 );
				rc = -1;
				goto done;
			}
		}

		if ( cb ) {
			for ( mcp = &mp->mp_cb; *mcp; mcp = &(*mcp)->mc_next )
				/* go to tail */ ;
		
			/* NOTE: we do not clear cb->mc_next, so this function
			 * can be used to append a list of callbacks */
			(*mcp) = cb;
		}

done:;
		if ( rc ) {
			if ( *atp ) {
				attrs_free( *atp );
				*atp = NULL;
			}
		}

		if ( freeit ) {
			ber_memfree( ndn.bv_val );
		}

		if ( e ) {
			monitor_cache_release( mi, e );
		}

	} else {
		entry_limbo_t	**elpp, el = { 0 };

		el.el_type = LIMBO_ATTRS;
		if ( !BER_BVISNULL( &ndn ) ) {
			ber_dupbv( &el.el_ndn, &ndn );
		}
		if ( !BER_BVISNULL( base ) ) {
			ber_dupbv( &el.el_base, base);
		}
		el.el_scope = scope;
		if ( !BER_BVISNULL( filter ) ) {
			ber_dupbv( &el.el_filter, filter );
		}

		el.el_a = attrs_dup( a );
		el.el_cb = cb;

		for ( elpp = (entry_limbo_t **)&mi->mi_entry_limbo;
				*elpp;
				elpp = &(*elpp)->el_next )
			/* go to last */;

		*elpp = (entry_limbo_t *)ch_malloc( sizeof( entry_limbo_t ) );
		if ( *elpp == NULL ) {
			el.el_e->e_private = NULL;
			entry_free( el.el_e );
			return -1;
		}

		el.el_next = NULL;
		**elpp = el;
	}

	return 0;
}

int
monitor_back_register_entry_callback(
	struct berval		*ndn,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter )
{
	return monitor_back_register_entry_attrs( ndn, NULL, cb,
			base, scope, filter );
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
monitor_back_get_subsys_by_dn(
	struct berval	*ndn,
	int		sub )
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
	BackendInfo	*bi )
{
	static char		*controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		NULL
	};

	static ConfigTable monitorcfg[] = {
		{ NULL, NULL, 0, 0, 0, ARG_IGNORED,
			NULL, NULL, NULL, NULL }
	};

	static ConfigOCs monitorocs[] = {
		{ "( OLcfgDbOc:4.1 "
			"NAME 'olcMonitorConfig' "
			"DESC 'Monitor backend configuration' "
			"SUP olcDatabaseConfig "
			")",
			 	Cft_Database, monitorcfg },
		{ NULL, 0, NULL }
	};

	struct m_s {
		char	*name;
		char	*schema;
		slap_mask_t flags;
		int	offset;
	} moc[] = {
		{ "monitor", "( 1.3.6.1.4.1.4203.666.3.16.1 "
			"NAME 'monitor' "
			"DESC 'OpenLDAP system monitoring' "
			"SUP top STRUCTURAL "
			"MUST cn "
			"MAY ( "
				"description "
				"$ seeAlso "
				"$ labeledURI "
				"$ monitoredInfo "
				"$ managedInfo "
				"$ monitorOverlay "
			") )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitor) },
		{ "monitorServer", "( 1.3.6.1.4.1.4203.666.3.16.2 "
			"NAME 'monitorServer' "
			"DESC 'Server monitoring root entry' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorServer) },
		{ "monitorContainer", "( 1.3.6.1.4.1.4203.666.3.16.3 "
			"NAME 'monitorContainer' "
			"DESC 'monitor container class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorContainer) },
		{ "monitorCounterObject", "( 1.3.6.1.4.1.4203.666.3.16.4 "
			"NAME 'monitorCounterObject' "
			"DESC 'monitor counter class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorCounterObject) },
		{ "monitorOperation", "( 1.3.6.1.4.1.4203.666.3.16.5 "
			"NAME 'monitorOperation' "
			"DESC 'monitor operation class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorOperation) },
		{ "monitorConnection", "( 1.3.6.1.4.1.4203.666.3.16.6 "
			"NAME 'monitorConnection' "
			"DESC 'monitor connection class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitorConnection) },
		{ "managedObject", "( 1.3.6.1.4.1.4203.666.3.16.7 "
			"NAME 'managedObject' "
			"DESC 'monitor managed entity class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_managedObject) },
		{ "monitoredObject", "( 1.3.6.1.4.1.4203.666.3.16.8 "
			"NAME 'monitoredObject' "
			"DESC 'monitor monitored entity class' "
			"SUP monitor STRUCTURAL )", SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
			offsetof(monitor_info_t, mi_oc_monitoredObject) },
		{ NULL, NULL, 0, -1 }
	}, mat[] = {
		{ "monitoredInfo", "( 1.3.6.1.4.1.4203.666.1.55.1 "
			"NAME 'monitoredInfo' "
			"DESC 'monitored info' "
			/* "SUP name " */
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitoredInfo) },
		{ "managedInfo", "( 1.3.6.1.4.1.4203.666.1.55.2 "
			"NAME 'managedInfo' "
			"DESC 'monitor managed info' "
			"SUP name )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_managedInfo) },
		{ "monitorCounter", "( 1.3.6.1.4.1.4203.666.1.55.3 "
			"NAME 'monitorCounter' "
			"DESC 'monitor counter' "
			"EQUALITY integerMatch "
			"ORDERING integerOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorCounter) },
		{ "monitorOpCompleted", "( 1.3.6.1.4.1.4203.666.1.55.4 "
			"NAME 'monitorOpCompleted' "
			"DESC 'monitor completed operations' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOpCompleted) },
		{ "monitorOpInitiated", "( 1.3.6.1.4.1.4203.666.1.55.5 "
			"NAME 'monitorOpInitiated' "
			"DESC 'monitor initiated operations' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOpInitiated) },
		{ "monitorConnectionNumber", "( 1.3.6.1.4.1.4203.666.1.55.6 "
			"NAME 'monitorConnectionNumber' "
			"DESC 'monitor connection number' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionNumber) },
		{ "monitorConnectionAuthzDN", "( 1.3.6.1.4.1.4203.666.1.55.7 "
			"NAME 'monitorConnectionAuthzDN' "
			"DESC 'monitor connection authorization DN' "
			/* "SUP distinguishedName " */
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionAuthzDN) },
		{ "monitorConnectionLocalAddress", "( 1.3.6.1.4.1.4203.666.1.55.8 "
			"NAME 'monitorConnectionLocalAddress' "
			"DESC 'monitor connection local address' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionLocalAddress) },
		{ "monitorConnectionPeerAddress", "( 1.3.6.1.4.1.4203.666.1.55.9 "
			"NAME 'monitorConnectionPeerAddress' "
			"DESC 'monitor connection peer address' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionPeerAddress) },
		{ "monitorTimestamp", "( 1.3.6.1.4.1.4203.666.1.55.10 "
			"NAME 'monitorTimestamp' "
			"DESC 'monitor timestamp' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
			"SINGLE-VALUE "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorTimestamp) },
		{ "monitorOverlay", "( 1.3.6.1.4.1.4203.666.1.55.11 "
			"NAME 'monitorOverlay' "
			"DESC 'name of overlays defined for a given database' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorOverlay) },
		{ "readOnly", "( 1.3.6.1.4.1.4203.666.1.55.12 "
			"NAME 'readOnly' "
			"DESC 'read/write status of a given database' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_readOnly) },
		{ "restrictedOperation", "( 1.3.6.1.4.1.4203.666.1.55.13 "
			"NAME 'restrictedOperation' "
			"DESC 'name of restricted operation for a given database' "
			"SUP managedInfo )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_restrictedOperation ) },
		{ "monitorConnectionProtocol", "( 1.3.6.1.4.1.4203.666.1.55.14 "
			"NAME 'monitorConnectionProtocol' "
			"DESC 'monitor connection protocol' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionProtocol) },
		{ "monitorConnectionOpsReceived", "( 1.3.6.1.4.1.4203.666.1.55.15 "
			"NAME 'monitorConnectionOpsReceived' "
			"DESC 'monitor number of operations received by the connection' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionOpsReceived) },
		{ "monitorConnectionOpsExecuting", "( 1.3.6.1.4.1.4203.666.1.55.16 "
			"NAME 'monitorConnectionOpsExecuting' "
			"DESC 'monitor number of operations in execution within the connection' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionOpsExecuting) },
		{ "monitorConnectionOpsPending", "( 1.3.6.1.4.1.4203.666.1.55.17 "
			"NAME 'monitorConnectionOpsPending' "
			"DESC 'monitor number of pending operations within the connection' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionOpsPending) },
		{ "monitorConnectionOpsCompleted", "( 1.3.6.1.4.1.4203.666.1.55.18 "
			"NAME 'monitorConnectionOpsCompleted' "
			"DESC 'monitor number of operations completed within the connection' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionOpsCompleted) },
		{ "monitorConnectionGet", "( 1.3.6.1.4.1.4203.666.1.55.19 "
			"NAME 'monitorConnectionGet' "
			"DESC 'number of times connection_get() was called so far' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionGet) },
		{ "monitorConnectionRead", "( 1.3.6.1.4.1.4203.666.1.55.20 "
			"NAME 'monitorConnectionRead' "
			"DESC 'number of times connection_read() was called so far' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionRead) },
		{ "monitorConnectionWrite", "( 1.3.6.1.4.1.4203.666.1.55.21 "
			"NAME 'monitorConnectionWrite' "
			"DESC 'number of times connection_write() was called so far' "
			"SUP monitorCounter "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionWrite) },
		{ "monitorConnectionMask", "( 1.3.6.1.4.1.4203.666.1.55.22 "
			"NAME 'monitorConnectionMask' "
			"DESC 'monitor connection mask' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionMask) },
		{ "monitorConnectionListener", "( 1.3.6.1.4.1.4203.666.1.55.23 "
			"NAME 'monitorConnectionListener' "
			"DESC 'monitor connection listener' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionListener) },
		{ "monitorConnectionPeerDomain", "( 1.3.6.1.4.1.4203.666.1.55.24 "
			"NAME 'monitorConnectionPeerDomain' "
			"DESC 'monitor connection peer domain' "
			"SUP monitoredInfo "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionPeerDomain) },
		{ "monitorConnectionStartTime", "( 1.3.6.1.4.1.4203.666.1.55.25 "
			"NAME 'monitorConnectionStartTime' "
			"DESC 'monitor connection start time' "
			"SUP monitorTimestamp "
			"SINGLE-VALUE "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionStartTime) },
		{ "monitorConnectionActivityTime", "( 1.3.6.1.4.1.4203.666.1.55.26 "
			"NAME 'monitorConnectionActivityTime' "
			"DESC 'monitor connection activity time' "
			"SUP monitorTimestamp "
			"SINGLE-VALUE "
			"NO-USER-MODIFICATION "
			"USAGE directoryOperation )", SLAP_AT_FINAL|SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorConnectionActivityTime) },
		{ "monitorIsShadow", "( 1.3.6.1.4.1.4203.666.1.55.27 "
			"NAME 'monitorIsShadow' "
			"DESC 'TRUE if the database is shadow' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorIsShadow) },
		{ "monitorUpdateRef", "( 1.3.6.1.4.1.4203.666.1.55.28 "
			"NAME 'monitorUpdateRef' "
			"DESC 'update referral for shadow databases' "
			"SUP monitoredInfo "
			"SINGLE-VALUE "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorUpdateRef) },
		{ "monitorRuntimeConfig", "( 1.3.6.1.4.1.4203.666.1.55.29 "
			"NAME 'monitorRuntimeConfig' "
			"DESC 'TRUE if component allows runtime configuration' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE "
			"USAGE directoryOperation )", SLAP_AT_HIDE,
			offsetof(monitor_info_t, mi_ad_monitorRuntimeConfig) },
		{ NULL, NULL, 0, -1 }
	};

	int			i, rc;
	const char		*text;
	monitor_info_t		*mi = &monitor_info;

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

		code = at_add(at, 0, NULL, &err);
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

		code = oc_add(oc, 0, NULL, &err);
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

	bi->bi_controls = controls;

	bi->bi_init = 0;
	bi->bi_open = 0;
	bi->bi_config = monitor_back_config;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = monitor_back_db_init;
#if 0
	bi->bi_db_config = monitor_back_db_config;
#endif
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

	/*
	 * configuration objectClasses (fake)
	 */
	bi->bi_cf_ocs = monitorocs;

	rc = config_register_schema( monitorcfg, monitorocs );
	if ( rc ) {
		return rc;
	}

	return 0;
}

int
monitor_back_db_init(
	BackendDB	*be )
{
	int			rc;
	struct berval		dn = BER_BVC( SLAPD_MONITOR_DN ),
				pdn,
				ndn;
	BackendDB		*be2;

	monitor_subsys_t	*ms;

	/*
	 * register subsys
	 */
	for ( ms = known_monitor_subsys; ms->mss_name != NULL; ms++ ) {
		if ( monitor_back_register_subsys( ms ) ) {
			return -1;
		}
	}

	/*
	 * database monitor can be defined once only
	 */
	if ( be_monitor != NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"only one monitor database is allowed\n", 0, 0, 0 );
		return( -1 );
	}
	be_monitor = be;

	/* indicate system schema supported */
	SLAP_BFLAGS(be) |= SLAP_BFLAG_MONITOR;

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn, NULL );
	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"unable to normalize/pretty monitor DN \"%s\" (%d)\n",
			dn.bv_val, rc, 0 );
		return -1;
	}

	ber_bvarray_add( &be->be_suffix, &pdn );
	ber_bvarray_add( &be->be_nsuffix, &ndn );

	/* NOTE: only one monitor database is allowed,
	 * so we use static storage */
	ldap_pvt_thread_mutex_init( &monitor_info.mi_cache_mutex );

	be->be_private = &monitor_info;

	be2 = select_backend( &ndn, 0, 0 );
	if ( be2 != be ) {
		char	*type = be2->bd_info->bi_type;

		if ( overlay_is_over( be2 ) ) {
			slap_overinfo	*oi = (slap_overinfo *)be2->bd_info->bi_private;
			type = oi->oi_orig->bi_type;
		}

		Debug( LDAP_DEBUG_ANY,
			"\"monitor\" database serving namingContext \"%s\" "
			"is hidden by \"%s\" database serving namingContext \"%s\".\n",
			pdn.bv_val, type, be2->be_nsuffix[ 0 ].bv_val );
		return -1;
	}

	return 0;
}

int
monitor_back_db_open(
	BackendDB	*be )
{
	monitor_info_t 		*mi = (monitor_info_t *)be->be_private;
	struct monitor_subsys_t	**ms;
	Entry 			*e, **ep;
	monitor_entry_t		*mp;
	int			i;
	char 			buf[ BACKMONITOR_BUFSIZE ];
	struct berval		bv;
	struct tm		*tms;
#ifdef HAVE_GMTIME_R
	struct tm		tm_buf;
#endif
	static char		tmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];

	assert( be_monitor != NULL );
	if ( be != be_monitor ) {
		be_monitor = be;
	}

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
		"description: This subtree contains monitoring/managing objects.\n"
		"description: This object contains information about this server.\n"
		"description: Most of the information is held in operational"
		" attributes, which must be explicitly requested.\n"
		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		SLAPD_MONITOR_DN,
		mi->mi_oc_monitorServer->soc_cname.bv_val,
		mi->mi_oc_monitorServer->soc_cname.bv_val,
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

	bv.bv_val = strchr( (char *) Versionstr, '$' );
	if ( bv.bv_val != NULL ) {
		char	*end;

		bv.bv_val++;
		for ( ; bv.bv_val[ 0 ] == ' '; bv.bv_val++ )
			;

		end = strchr( bv.bv_val, '$' );
		if ( end != NULL ) {
			end--;

			for ( ; end > bv.bv_val && end[ 0 ] == ' '; end-- )
				;

			end++;

			bv.bv_len = end - bv.bv_val;

		} else {
			bv.bv_len = strlen( bv.bv_val );
		}

		if ( attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
					&bv, NULL ) ) {
			Debug( LDAP_DEBUG_ANY,
				"unable to add monitoredInfo to \"%s\" entry\n",
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

		if ( !BER_BVISNULL( &monitor_subsys[ i ]->mss_desc[ 0 ] ) ) {
			attr_merge_normalize( e, slap_schema.si_ad_description,
					monitor_subsys[ i ]->mss_desc, NULL );
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

	assert( be != NULL );

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

			switch ( el->el_type ) {
			case LIMBO_ENTRY:
				monitor_back_register_entry(
						el->el_e,
						el->el_cb );
				break;

			case LIMBO_ENTRY_PARENT:
				monitor_back_register_entry_parent(
						el->el_e,
						el->el_cb,
						&el->el_base,
						el->el_scope,
						&el->el_filter );
				break;
				

			case LIMBO_ATTRS:
				monitor_back_register_entry_attrs(
						&el->el_ndn,
						el->el_a,
						el->el_cb,
						&el->el_base,
						el->el_scope,
						&el->el_filter );
				break;

			case LIMBO_CB:
				monitor_back_register_entry_callback(
						&el->el_ndn,
						el->el_cb,
						&el->el_base,
						el->el_scope,
						&el->el_filter );
				break;

			default:
				assert( 0 );
			}

			if ( el->el_e ) {
				entry_free( el->el_e );
			}
			if ( el->el_a ) {
				attrs_free( el->el_a );
			}
			if ( !BER_BVISNULL( &el->el_ndn ) ) {
				ber_memfree( el->el_ndn.bv_val );
			}
			if ( !BER_BVISNULL( &el->el_base ) ) {
				ber_memfree( el->el_base.bv_val );
			}
			if ( !BER_BVISNULL( &el->el_filter ) ) {
				ber_memfree( el->el_filter.bv_val );
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
	char		**argv )
{
	/*
	 * eventually, will hold backend specific configuration parameters
	 */
	return SLAP_CONF_UNKNOWN;
}

#if 0
int
monitor_back_db_config(
	Backend     *be,
	const char  *fname,
	int         lineno,
	int         argc,
	char        **argv )
{
	monitor_info_t	*mi = ( monitor_info_t * )be->be_private;

	/*
	 * eventually, will hold database specific configuration parameters
	 */
	return SLAP_CONF_UNKNOWN;
}
#endif

int
monitor_back_db_destroy(
	BackendDB	*be )
{
	monitor_info_t	*mi = ( monitor_info_t * )be->be_private;

	if ( mi == NULL ) {
		return -1;
	}

	/*
	 * FIXME: destroys all the data
	 */
	/* NOTE: mi points to static storage; don't free it */
	
	(void)monitor_cache_destroy( mi );

	if ( monitor_subsys ) {
		int	i;

		for ( i = 0; monitor_subsys[ i ] != NULL; i++ ) {
			if ( monitor_subsys[ i ]->mss_destroy ) {
				monitor_subsys[ i ]->mss_destroy( be, monitor_subsys[ i ] );
			}

			if ( !BER_BVISNULL( &monitor_subsys[ i ]->mss_rdn ) ) {
				ch_free( monitor_subsys[ i ]->mss_rdn.bv_val );
			}

			if ( !BER_BVISNULL( &monitor_subsys[ i ]->mss_dn ) ) {
				ch_free( monitor_subsys[ i ]->mss_dn.bv_val );
			}

			if ( !BER_BVISNULL( &monitor_subsys[ i ]->mss_ndn ) ) {
				ch_free( monitor_subsys[ i ]->mss_ndn.bv_val );
			}
		}

		ch_free( monitor_subsys );
	}
	
	ldap_pvt_thread_mutex_destroy( &monitor_info.mi_cache_mutex );

	be->be_private = NULL;

	return 0;
}

#if SLAPD_MONITOR == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( monitor )

#endif /* SLAPD_MONITOR == SLAPD_MOD_DYNAMIC */


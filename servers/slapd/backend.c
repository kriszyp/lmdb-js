/* backend.c - routines for dealing with back-end databases */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */


#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <sys/stat.h>

#include "slap.h"
#include "lutil.h"
#include "lber_pvt.h"

#include "ldap_rq.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

/*
 * If a module is configured as dynamic, its header should not
 * get included into slapd. While this is a general rule and does
 * not have much of an effect in UNIX, this rule should be adhered
 * to for Windows, where dynamic object code should not be implicitly
 * imported into slapd without appropriate __declspec(dllimport) directives.
 */

#if SLAPD_BDB == SLAPD_MOD_STATIC
#include "back-bdb/external.h"
#endif
#if SLAPD_DNSSRV == SLAPD_MOD_STATIC
#include "back-dnssrv/external.h"
#endif
#if SLAPD_HDB == SLAPD_MOD_STATIC
#include "back-hdb/external.h"
#endif
#if SLAPD_LDAP == SLAPD_MOD_STATIC
#include "back-ldap/external.h"
#endif
#if SLAPD_LDBM == SLAPD_MOD_STATIC
#include "back-ldbm/external.h"
#endif
#if SLAPD_META == SLAPD_MOD_STATIC
#include "back-meta/external.h"
#endif
#if SLAPD_MONITOR == SLAPD_MOD_STATIC
#include "back-monitor/external.h"
#endif
#if SLAPD_NULL == SLAPD_MOD_STATIC
#include "back-null/external.h"
#endif
#if SLAPD_PASSWD == SLAPD_MOD_STATIC
#include "back-passwd/external.h"
#endif
#if SLAPD_PERL == SLAPD_MOD_STATIC
#include "back-perl/external.h"
#endif
#if SLAPD_RELAY == SLAPD_MOD_STATIC
#include "back-relay/external.h"
#endif
#if SLAPD_SHELL == SLAPD_MOD_STATIC
#include "back-shell/external.h"
#endif
#if SLAPD_TCL == SLAPD_MOD_STATIC
#include "back-tcl/external.h"
#endif
#if SLAPD_SQL == SLAPD_MOD_STATIC
#include "back-sql/external.h"
#endif
#if SLAPD_PRIVATE == SLAPD_MOD_STATIC
#include "private/external.h"
#endif

static BackendInfo binfo[] = {
#if SLAPD_BDB == SLAPD_MOD_STATIC
	{"bdb",	bdb_initialize},
#endif
#if SLAPD_DNSSRV == SLAPD_MOD_STATIC
	{"dnssrv",	dnssrv_back_initialize},
#endif
#if SLAPD_HDB == SLAPD_MOD_STATIC
	{"hdb",	hdb_initialize},
#endif
#if SLAPD_LDAP == SLAPD_MOD_STATIC
	{"ldap",	ldap_back_initialize},
#endif
#if SLAPD_LDBM == SLAPD_MOD_STATIC
	{"ldbm",	ldbm_back_initialize},
#endif
#if SLAPD_META == SLAPD_MOD_STATIC
	{"meta",	meta_back_initialize},
#endif
#if SLAPD_MONITOR == SLAPD_MOD_STATIC
	{"monitor",	monitor_back_initialize},
#endif
#if SLAPD_NULL == SLAPD_MOD_STATIC
	{"null",	null_back_initialize},
#endif
#if SLAPD_PASSWD == SLAPD_MOD_STATIC
	{"passwd",	passwd_back_initialize},
#endif
#if SLAPD_PERL == SLAPD_MOD_STATIC
	{"perl",	perl_back_initialize},
#endif
#if SLAPD_RELAY == SLAPD_MOD_STATIC
	{"relay",	relay_back_initialize},
#endif
#if SLAPD_SHELL == SLAPD_MOD_STATIC
	{"shell",	shell_back_initialize},
#endif
#if SLAPD_TCL == SLAPD_MOD_STATIC
	{"tcl",		tcl_back_initialize},
#endif
#if SLAPD_SQL == SLAPD_MOD_STATIC
	{"sql",		sql_back_initialize},
#endif
	/* for any private backend */
#if SLAPD_PRIVATE == SLAPD_MOD_STATIC
	{"private",	private_back_initialize},
#endif
	{NULL}
};

int			nBackendInfo = 0;
BackendInfo	*backendInfo = NULL;

int			nBackendDB = 0; 
BackendDB	*backendDB = NULL;

ldap_pvt_thread_pool_t	syncrepl_pool;
int			syncrepl_pool_max = SLAP_MAX_SYNCREPL_THREADS;

int backend_init(void)
{
	int rc = -1;

	ldap_pvt_thread_pool_init( &syncrepl_pool, syncrepl_pool_max, 0 );

	if((nBackendInfo != 0) || (backendInfo != NULL)) {
		/* already initialized */
#ifdef NEW_LOGGING
		LDAP_LOG( BACKEND, ERR, 
			"backend_init:  backend already initialized\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"backend_init: already initialized.\n", 0, 0, 0 );
#endif
		return -1;
	}

	for( ;
		binfo[nBackendInfo].bi_type != NULL;
		nBackendInfo++ )
	{
		assert( binfo[nBackendInfo].bi_init );

		rc = binfo[nBackendInfo].bi_init( &binfo[nBackendInfo] );

		if(rc != 0) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACKEND, INFO, 
				"backend_init:  initialized for type \"%s\"\n",
				binfo[nBackendInfo].bi_type, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"backend_init: initialized for type \"%s\"\n",
				binfo[nBackendInfo].bi_type, 0, 0 );
#endif
			/* destroy those we've already inited */
			for( nBackendInfo--;
				nBackendInfo >= 0 ;
				nBackendInfo-- )
			{ 
				if ( binfo[nBackendInfo].bi_destroy ) {
					binfo[nBackendInfo].bi_destroy(
						&binfo[nBackendInfo] );
				}
			}
			return rc;
		}
	}

	if ( nBackendInfo > 0) {
		backendInfo = binfo;
		return 0;
	}

#ifdef SLAPD_MODULES	
	return 0;
#else

#ifdef NEW_LOGGING
	LDAP_LOG( BACKEND, ERR, "backend_init: failed\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY,
		"backend_init: failed\n",
		0, 0, 0 );
#endif

	return rc;
#endif /* SLAPD_MODULES */
}

int backend_add(BackendInfo *aBackendInfo)
{
	int rc = 0;

	if ( aBackendInfo->bi_init == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACKEND, ERR, "backend_add: "
			"backend type \"%s\" does not have the (mandatory)init function\n",
			aBackendInfo->bi_type, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "backend_add: "
			"backend type \"%s\" does not have the (mandatory)init function\n",
			aBackendInfo->bi_type, 0, 0 );
#endif
		return -1;
	}

   if ((rc = aBackendInfo->bi_init(aBackendInfo)) != 0) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACKEND, ERR, 
			"backend_add:  initialization for type \"%s\" failed\n",
			aBackendInfo->bi_type, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"backend_add:  initialization for type \"%s\" failed\n",
			aBackendInfo->bi_type, 0, 0 );
#endif
		return rc;
   }

	/* now add the backend type to the Backend Info List */
	{
		BackendInfo *newBackendInfo = 0;

		/* if backendInfo == binfo no deallocation of old backendInfo */
		if (backendInfo == binfo) {
			newBackendInfo = ch_calloc(nBackendInfo + 1, sizeof(BackendInfo));
			AC_MEMCPY(newBackendInfo, backendInfo,
				sizeof(BackendInfo) * nBackendInfo);
		} else {
			newBackendInfo = ch_realloc(backendInfo,
				sizeof(BackendInfo) * (nBackendInfo + 1));
		}

		AC_MEMCPY(&newBackendInfo[nBackendInfo], aBackendInfo,
			sizeof(BackendInfo));
		backendInfo = newBackendInfo;
		nBackendInfo++;
		return 0;
	}
}

/* startup a specific backend database */
int backend_startup_one(Backend *be)
{
	int rc = 0;

	assert(be);

	be->be_pending_csn_list = (struct be_pcl *)
		ch_calloc( 1, sizeof( struct be_pcl ));
	build_new_dn( &be->be_context_csn, be->be_nsuffix,
		(struct berval *)&slap_ldapsync_cn_bv, NULL );

	LDAP_TAILQ_INIT( be->be_pending_csn_list );

#ifdef NEW_LOGGING
	LDAP_LOG( BACKEND, DETAIL1, "backend_startup:  starting \"%s\"\n",
		be->be_suffix ? be->be_suffix[0].bv_val : "(unknown)",
		0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"backend_startup: starting \"%s\"\n",
		be->be_suffix ? be->be_suffix[0].bv_val : "(unknown)",
		0, 0 );
#endif
	if ( be->bd_info->bi_db_open ) {
		rc = be->bd_info->bi_db_open( be );
		if ( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACKEND, CRIT, 
				"backend_startup: bi_db_open failed! (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_db_open failed! (%d)\n",
				rc, 0, 0 );
#endif
		}
	}
	return rc;
}

int backend_startup(Backend *be)
{
	int i;
	int rc = 0;

	if( ! ( nBackendDB > 0 ) ) {
		/* no databases */
#ifdef NEW_LOGGING
		LDAP_LOG( BACKEND, INFO, 
			"backend_startup: %d databases to startup. \n", nBackendDB, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"backend_startup: %d databases to startup.\n",
			nBackendDB, 0, 0 );
#endif
		return 1;
	}

	if(be != NULL) {
		if ( be->bd_info->bi_open ) {
			rc = be->bd_info->bi_open( be->bd_info );
			if ( rc != 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACKEND, CRIT,
					"backend_startup: bi_open failed!\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_open failed!\n",
					0, 0, 0 );
#endif

				return rc;
			}
		}

		return backend_startup_one( be );
	}

	/* open each backend type */
	for( i = 0; i < nBackendInfo; i++ ) {
		if( backendInfo[i].bi_nDB == 0) {
			/* no database of this type, don't open */
			continue;
		}

		if( backendInfo[i].bi_open ) {
			rc = backendInfo[i].bi_open(
				&backendInfo[i] );
			if ( rc != 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACKEND, CRIT, 
					"backend_startup: bi_open %d failed!\n", i, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_open %d failed!\n",
					i, 0, 0 );
#endif
				return rc;
			}
		}
	}

	ldap_pvt_thread_mutex_init( &syncrepl_rq.rq_mutex );
	LDAP_STAILQ_INIT( &syncrepl_rq.task_list );
	LDAP_STAILQ_INIT( &syncrepl_rq.run_list );

	/* open each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		if ( backendDB[i].be_suffix == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACKEND, CRIT, 
				"backend_startup: warning, database %d (%s) "
				"has no suffix\n",
				i, backendDB[i].bd_info->bi_type, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: warning, database %d (%s) "
				"has no suffix\n",
				i, backendDB[i].bd_info->bi_type, 0 );
#endif
		}
		/* append global access controls */
		acl_append( &backendDB[i].be_acl, global_acl );

		rc = backend_startup_one( &backendDB[i] );

		if ( rc ) return rc;


		if ( !LDAP_STAILQ_EMPTY( &backendDB[i].be_syncinfo )) {
			syncinfo_t *si;

			if ( !( backendDB[i].be_search && backendDB[i].be_add &&
				backendDB[i].be_modify && backendDB[i].be_delete )) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACKEND, CRIT, 
					"backend_startup: database(%d) does not support "
					"operations required for syncrepl", i, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: database(%d) does not support "
					"operations required for syncrepl", i, 0, 0 );
#endif
				continue;
			}

			LDAP_STAILQ_FOREACH( si, &backendDB[i].be_syncinfo, si_next ) {
				si->si_be = &backendDB[i];
				init_syncrepl( si );
				ldap_pvt_thread_mutex_lock( &syncrepl_rq.rq_mutex );
				ldap_pvt_runqueue_insert( &syncrepl_rq,
						si->si_interval, do_syncrepl, (void *) si );
				ldap_pvt_thread_mutex_unlock( &syncrepl_rq.rq_mutex );
			}
		}
	}

	return rc;
}

int backend_num( Backend *be )
{
	int i;

	if( be == NULL ) return -1;

	for( i = 0; i < nBackendDB; i++ ) {
		if( be == &backendDB[i] ) return i;
	}
	return -1;
}

int backend_shutdown( Backend *be )
{
	int i;
	int rc = 0;

	if( be != NULL ) {
		/* shutdown a specific backend database */

		if ( be->bd_info->bi_nDB == 0 ) {
			/* no database of this type, we never opened it */
			return 0;
		}

		if ( be->bd_info->bi_db_close ) {
			be->bd_info->bi_db_close( be );
		}

		if( be->bd_info->bi_close ) {
			be->bd_info->bi_close( be->bd_info );
		}

		return 0;
	}

	/* close each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		if ( backendDB[i].bd_info->bi_db_close ) {
			backendDB[i].bd_info->bi_db_close(
				&backendDB[i] );
		}

		if(rc != 0) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACKEND, NOTICE, 
				"backend_shutdown: bi_close %s failed!\n",
				backendDB[i].be_type, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"backend_close: bi_close %s failed!\n",
				backendDB[i].be_type, 0, 0 );
#endif
		}
	}

	/* close each backend type */
	for( i = 0; i < nBackendInfo; i++ ) {
		if( backendInfo[i].bi_nDB == 0 ) {
			/* no database of this type */
			continue;
		}

		if( backendInfo[i].bi_close ) {
			backendInfo[i].bi_close(
				&backendInfo[i] );
		}
	}

	return 0;
}

int backend_destroy(void)
{
	int i;
	BackendDB *bd;

	ldap_pvt_thread_pool_destroy( &syncrepl_pool, 1 );

	/* destroy each backend database */
	for( i = 0, bd = backendDB; i < nBackendDB; i++, bd++ ) {
		if ( bd->bd_info->bi_db_destroy ) {
			bd->bd_info->bi_db_destroy( bd );
		}
		ber_bvarray_free( bd->be_suffix );
		ber_bvarray_free( bd->be_nsuffix );
		if ( bd->be_rootdn.bv_val ) free( bd->be_rootdn.bv_val );
		if ( bd->be_rootndn.bv_val ) free( bd->be_rootndn.bv_val );
		if ( bd->be_rootpw.bv_val ) free( bd->be_rootpw.bv_val );
		if ( bd->be_context_csn.bv_val ) free( bd->be_context_csn.bv_val );
		acl_destroy( bd->be_acl, global_acl );
	}
	free( backendDB );

	/* destroy each backend type */
	for( i = 0; i < nBackendInfo; i++ ) {
		if( backendInfo[i].bi_destroy ) {
			backendInfo[i].bi_destroy(
				&backendInfo[i] );
		}
	}

#ifdef SLAPD_MODULES
	if (backendInfo != binfo) {
	   free(backendInfo);
	}
#endif /* SLAPD_MODULES */

	nBackendInfo = 0;
	backendInfo = NULL;

	return 0;
}

BackendInfo* backend_info(const char *type)
{
	int i;

	/* search for the backend type */
	for( i = 0; i < nBackendInfo; i++ ) {
		if( strcasecmp(backendInfo[i].bi_type, type) == 0 ) {
			return &backendInfo[i];
		}
	}

	return NULL;
}


BackendDB *
backend_db_init(
    const char	*type )
{
	Backend	*be;
	BackendInfo *bi = backend_info(type);
	int	rc = 0;

	if( bi == NULL ) {
		fprintf( stderr, "Unrecognized database type (%s)\n", type );
		return NULL;
	}

	backendDB = (BackendDB *) ch_realloc(
			(char *) backendDB,
		    (nBackendDB + 1) * sizeof(Backend) );

	memset( &backendDB[nbackends], '\0', sizeof(Backend) );

	be = &backends[nbackends++];

	be->bd_info = bi;
	be->be_def_limit = deflimit;
	be->be_dfltaccess = global_default_access;

	be->be_restrictops = global_restrictops;
	be->be_requires = global_requires;
	be->be_ssf_set = global_ssf_set;

	be->be_context_csn.bv_len = 0;
	be->be_context_csn.bv_val = NULL;
	ldap_pvt_thread_mutex_init( &be->be_pcl_mutex );
	ldap_pvt_thread_mutex_init( &be->be_context_csn_mutex );

	LDAP_STAILQ_INIT( &be->be_syncinfo );

 	/* assign a default depth limit for alias deref */
	be->be_max_deref_depth = SLAPD_DEFAULT_MAXDEREFDEPTH; 

	if(bi->bi_db_init) {
		rc = bi->bi_db_init( be );
	}

	if(rc != 0) {
		fprintf( stderr, "database init failed (%s)\n", type );
		nbackends--;
		return NULL;
	}

	bi->bi_nDB++;
	return( be );
}

void
be_db_close( void )
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].bd_info->bi_db_close ) {
			(*backends[i].bd_info->bi_db_close)( &backends[i] );
		}
	}
}

Backend *
select_backend(
	struct berval * dn,
	int manageDSAit,
	int noSubs )
{
	int	i, j;
	ber_len_t len, dnlen = dn->bv_len;
	Backend *be = NULL;

	for ( i = 0; i < nbackends; i++ ) {
		for ( j = 0; backends[i].be_nsuffix != NULL &&
		    backends[i].be_nsuffix[j].bv_val != NULL; j++ )
		{
			if ( ( SLAP_GLUE_SUBORDINATE( &backends[i] ) )
				&& noSubs )
			{
			  	continue;
			}

			len = backends[i].be_nsuffix[j].bv_len;

			if ( len > dnlen ) {
				/* suffix is longer than DN */
				continue;
			}
			
			/*
			 * input DN is normalized, so the separator check
			 * need not look at escaping
			 */
			if ( len && len < dnlen &&
				!DN_SEPARATOR( dn->bv_val[(dnlen-len)-1] ))
			{
				continue;
			}

			if ( strcmp( backends[i].be_nsuffix[j].bv_val,
				&dn->bv_val[dnlen-len] ) == 0 )
			{
				if( be == NULL ) {
					be = &backends[i];

					if( manageDSAit && len == dnlen &&
						!SLAP_GLUE_SUBORDINATE( be ) ) {
						continue;
					}
				} else {
					be = &backends[i];
				}
				return be;
			}
		}
	}

	return be;
}

int
be_issuffix(
    Backend *be,
    struct berval *bvsuffix )
{
	int	i;

	for ( i = 0;
		be->be_nsuffix != NULL && be->be_nsuffix[i].bv_val != NULL;
		i++ )
	{
		if ( bvmatch( &be->be_nsuffix[i], bvsuffix ) ) {
			return( 1 );
		}
	}

	return( 0 );
}

int
be_isroot_dn( Backend *be, struct berval *ndn )
{
	if ( !ndn->bv_len ) {
		return( 0 );
	}

	if ( !be->be_rootndn.bv_len ) {
		return( 0 );
	}

	return dn_match( &be->be_rootndn, ndn );
}

int
be_sync_update( Operation *op )
{
	return ( SLAP_SYNC_SHADOW( op->o_bd ) && syncrepl_isupdate( op ) );
}

int
be_slurp_update( Operation *op )
{
	return ( SLAP_SLURP_SHADOW( op->o_bd ) &&
		be_isupdate_dn( op->o_bd, &op->o_ndn ));
}

int
be_shadow_update( Operation *op )
{
	return ( SLAP_SHADOW( op->o_bd ) &&
		( syncrepl_isupdate( op ) || be_isupdate_dn( op->o_bd, &op->o_ndn )));
}

int
be_isupdate_dn( Backend *be, struct berval *ndn )
{
	if ( !ndn->bv_len ) return( 0 );

	if ( !be->be_update_ndn.bv_len ) return( 0 );

	return dn_match( &be->be_update_ndn, ndn );
}

struct berval *
be_root_dn( Backend *be )
{
	return &be->be_rootdn;
}

int
be_isroot( Operation *op )
{
	return be_isroot_dn( op->o_bd, &op->o_ndn );
}

int
be_isroot_pw( Operation *op )
{
	int result;

	if ( ! be_isroot_dn( op->o_bd, &op->o_req_ndn ) ) {
		return 0;
	}

	if( op->o_bd->be_rootpw.bv_len == 0 ) {
		return 0;
	}

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = op->o_conn->c_sasl_authctx;
#endif
#endif

	result = lutil_passwd( &op->o_bd->be_rootpw, &op->orb_cred, NULL, NULL );

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = NULL;
#endif
	ldap_pvt_thread_mutex_unlock( &passwd_mutex );
#endif

	return result == 0;
}

int
be_entry_release_rw(
	Operation *op,
	Entry *e,
	int rw )
{
	if ( op->o_bd->be_release ) {
		/* free and release entry from backend */
		return op->o_bd->be_release( op, e, rw );
	} else {
		/* free entry */
		entry_free( e );
		return 0;
	}
}

int
backend_unbind( Operation *op, SlapReply *rs )
{
	int		i;

	for ( i = 0; i < nbackends; i++ ) {
#if defined( LDAP_SLAPI )
		if ( op->o_pb ) {
			int rc;
			if ( i == 0 ) slapi_int_pblock_set_operation( op->o_pb, op );
			slapi_pblock_set( op->o_pb, SLAPI_BACKEND, (void *)&backends[i] );
			rc = slapi_int_call_plugins( &backends[i],
				SLAPI_PLUGIN_PRE_UNBIND_FN, (Slapi_PBlock *)op->o_pb );
			if ( rc < 0 ) {
				/*
				 * A preoperation plugin failure will abort the
				 * entire operation.
				 */
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, INFO,
					"do_bind: Unbind preoperation plugin failed\n",
					0, 0, 0);
#else
				Debug(LDAP_DEBUG_TRACE,
					"do_bind: Unbind preoperation plugin failed\n",
					0, 0, 0);
#endif
				return 0;
			}
		}
#endif /* defined( LDAP_SLAPI ) */

		if ( backends[i].be_unbind ) {
			op->o_bd = &backends[i];
			(*backends[i].be_unbind)( op, rs );
		}

#if defined( LDAP_SLAPI )
		if ( op->o_pb != NULL && slapi_int_call_plugins( &backends[i],
			SLAPI_PLUGIN_POST_UNBIND_FN, (Slapi_PBlock *)op->o_pb ) < 0 )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO,
				"do_unbind: Unbind postoperation plugins failed\n",
				0, 0, 0);
#else
			Debug(LDAP_DEBUG_TRACE,
				"do_unbind: Unbind postoperation plugins failed\n",
				0, 0, 0);
#endif
		}
#endif /* defined( LDAP_SLAPI ) */
	}

	return 0;
}

int
backend_connection_init(
	Connection   *conn )
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_connection_init ) {
			(*backends[i].be_connection_init)( &backends[i], conn);
		}
	}

	return 0;
}

int
backend_connection_destroy(
	Connection   *conn )
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_connection_destroy ) {
			(*backends[i].be_connection_destroy)( &backends[i], conn);
		}
	}

	return 0;
}

static int
backend_check_controls(
	Operation *op,
	SlapReply *rs )
{
	LDAPControl **ctrls = op->o_ctrls;
	rs->sr_err = LDAP_SUCCESS;

	if( ctrls ) {
		for( ; *ctrls != NULL ; ctrls++ ) {
			if( (*ctrls)->ldctl_iscritical && !ldap_charray_inlist(
				op->o_bd->be_controls, (*ctrls)->ldctl_oid ) )
			{
				rs->sr_text = "control unavailable in context";
				rs->sr_err = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
				break;
			}
		}
	}

	return rs->sr_err;
}

int
backend_check_restrictions(
	Operation *op,
	SlapReply *rs,
	struct berval *opdata )
{
	slap_mask_t restrictops;
	slap_mask_t requires;
	slap_mask_t opflag;
	slap_mask_t exopflag = 0;
	slap_ssf_set_t *ssf;
	int updateop = 0;
	int starttls = 0;
	int session = 0;

	if( op->o_bd ) {
		if ( backend_check_controls( op, rs ) != LDAP_SUCCESS ) {
			return rs->sr_err;
		}

		restrictops = op->o_bd->be_restrictops;
		requires = op->o_bd->be_requires;
		ssf = &op->o_bd->be_ssf_set;

	} else {
		restrictops = global_restrictops;
		requires = global_requires;
		ssf = &global_ssf_set;
	}

	switch( op->o_tag ) {
	case LDAP_REQ_ADD:
		opflag = SLAP_RESTRICT_OP_ADD;
		updateop++;
		break;
	case LDAP_REQ_BIND:
		opflag = SLAP_RESTRICT_OP_BIND;
		session++;
		break;
	case LDAP_REQ_COMPARE:
		opflag = SLAP_RESTRICT_OP_COMPARE;
		break;
	case LDAP_REQ_DELETE:
		updateop++;
		opflag = SLAP_RESTRICT_OP_DELETE;
		break;
	case LDAP_REQ_EXTENDED:
		opflag = SLAP_RESTRICT_OP_EXTENDED;

		if( !opdata ) {
			/* treat unspecified as a modify */
			opflag = SLAP_RESTRICT_OP_MODIFY;
			updateop++;
			break;
		}

		if( bvmatch( opdata, &slap_EXOP_START_TLS ) ) {
			session++;
			starttls++;
			exopflag = SLAP_RESTRICT_EXOP_START_TLS;
			break;
		}

		if( bvmatch( opdata, &slap_EXOP_WHOAMI ) ) {
			exopflag = SLAP_RESTRICT_EXOP_WHOAMI;
			break;
		}

		if ( bvmatch( opdata, &slap_EXOP_CANCEL ) ) {
			exopflag = SLAP_RESTRICT_EXOP_CANCEL;
			break;
		}

		if ( bvmatch( opdata, &slap_EXOP_MODIFY_PASSWD ) ) {
			exopflag = SLAP_RESTRICT_EXOP_MODIFY_PASSWD;
			updateop++;
			break;
		}

		/* treat everything else as a modify */
		opflag = SLAP_RESTRICT_OP_MODIFY;
		updateop++;
		break;

	case LDAP_REQ_MODIFY:
		updateop++;
		opflag = SLAP_RESTRICT_OP_MODIFY;
		break;
	case LDAP_REQ_RENAME:
		updateop++;
		opflag = SLAP_RESTRICT_OP_RENAME;
		break;
	case LDAP_REQ_SEARCH:
		opflag = SLAP_RESTRICT_OP_SEARCH;
		break;
	case LDAP_REQ_UNBIND:
		session++;
		opflag = 0;
		break;
	default:
		rs->sr_text = "restrict operations internal error";
		rs->sr_err = LDAP_OTHER;
		return rs->sr_err;
	}

	if ( !starttls ) {
		/* these checks don't apply to StartTLS */

		rs->sr_err = LDAP_CONFIDENTIALITY_REQUIRED;
		if( op->o_transport_ssf < ssf->sss_transport ) {
			rs->sr_text = op->o_transport_ssf
				? "stronger transport confidentiality required"
				: "transport confidentiality required";
			return rs->sr_err;
		}

		if( op->o_tls_ssf < ssf->sss_tls ) {
			rs->sr_text = op->o_tls_ssf
				? "stronger TLS confidentiality required"
				: "TLS confidentiality required";
			return rs->sr_err;
		}


		if( op->o_tag == LDAP_REQ_BIND && opdata == NULL ) {
			/* simple bind specific check */
			if( op->o_ssf < ssf->sss_simple_bind ) {
				rs->sr_text = op->o_ssf
					? "stronger confidentiality required"
					: "confidentiality required";
				return rs->sr_err;
			}
		}

		if( op->o_tag != LDAP_REQ_BIND || opdata == NULL ) {
			/* these checks don't apply to SASL bind */

			if( op->o_sasl_ssf < ssf->sss_sasl ) {
				rs->sr_text = op->o_sasl_ssf
					? "stronger SASL confidentiality required"
					: "SASL confidentiality required";
				return rs->sr_err;
			}

			if( op->o_ssf < ssf->sss_ssf ) {
				rs->sr_text = op->o_ssf
					? "stronger confidentiality required"
					: "confidentiality required";
				return rs->sr_err;
			}
		}

		if( updateop ) {
			if( op->o_transport_ssf < ssf->sss_update_transport ) {
				rs->sr_text = op->o_transport_ssf
					? "stronger transport confidentiality required for update"
					: "transport confidentiality required for update";
				return rs->sr_err;
			}

			if( op->o_tls_ssf < ssf->sss_update_tls ) {
				rs->sr_text = op->o_tls_ssf
					? "stronger TLS confidentiality required for update"
					: "TLS confidentiality required for update";
				return rs->sr_err;
			}

			if( op->o_sasl_ssf < ssf->sss_update_sasl ) {
				rs->sr_text = op->o_sasl_ssf
					? "stronger SASL confidentiality required for update"
					: "SASL confidentiality required for update";
				return rs->sr_err;
			}

			if( op->o_ssf < ssf->sss_update_ssf ) {
				rs->sr_text = op->o_ssf
					? "stronger confidentiality required for update"
					: "confidentiality required for update";
				return rs->sr_err;
			}

			if( !( global_allows & SLAP_ALLOW_UPDATE_ANON ) &&
				op->o_ndn.bv_len == 0 )
			{
				rs->sr_text = "modifications require authentication";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}

#ifdef SLAP_X_LISTENER_MOD
			if ( op->o_conn->c_listener && ! ( op->o_conn->c_listener->sl_perms & ( op->o_ndn.bv_len > 0 ? S_IWUSR : S_IWOTH ) ) ) {
				/* no "w" mode means readonly */
				rs->sr_text = "modifications not allowed on this listener";
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				return rs->sr_err;
			}
#endif /* SLAP_X_LISTENER_MOD */
		}
	}

	if ( !session ) {
		/* these checks don't apply to Bind, StartTLS, or Unbind */

		if( requires & SLAP_REQUIRE_STRONG ) {
			/* should check mechanism */
			if( ( op->o_transport_ssf < ssf->sss_transport
				&& op->o_authtype == LDAP_AUTH_SIMPLE )
				|| op->o_dn.bv_len == 0 )
			{
				rs->sr_text = "strong(er) authentication required";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}
		}

		if( requires & SLAP_REQUIRE_SASL ) {
			if( op->o_authtype != LDAP_AUTH_SASL || op->o_dn.bv_len == 0 ) {
				rs->sr_text = "SASL authentication required";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}
		}
			
		if( requires & SLAP_REQUIRE_AUTHC ) {
			if( op->o_dn.bv_len == 0 ) {
				rs->sr_text = "authentication required";
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				return rs->sr_err;
			}
		}

		if( requires & SLAP_REQUIRE_BIND ) {
			int version;
			ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
			version = op->o_conn->c_protocol;
			ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

			if( !version ) {
				/* no bind has occurred */
				rs->sr_text = "BIND required";
				rs->sr_err = LDAP_OPERATIONS_ERROR;
				return rs->sr_err;
			}
		}

		if( requires & SLAP_REQUIRE_LDAP_V3 ) {
			if( op->o_protocol < LDAP_VERSION3 ) {
				/* no bind has occurred */
				rs->sr_text = "operation restricted to LDAPv3 clients";
				rs->sr_err = LDAP_OPERATIONS_ERROR;
				return rs->sr_err;
			}
		}

#ifdef SLAP_X_LISTENER_MOD
		if ( !starttls && op->o_dn.bv_len == 0 ) {
			if ( op->o_conn->c_listener &&
				!( op->o_conn->c_listener->sl_perms & S_IXOTH ))
		{
				/* no "x" mode means bind required */
				rs->sr_text = "bind required on this listener";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}
		}

		if ( !starttls && !updateop ) {
			if ( op->o_conn->c_listener &&
				!( op->o_conn->c_listener->sl_perms &
					( op->o_dn.bv_len > 0 ? S_IRUSR : S_IROTH )))
			{
				/* no "r" mode means no read */
				rs->sr_text = "read not allowed on this listener";
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				return rs->sr_err;
			}
		}
#endif /* SLAP_X_LISTENER_MOD */

	}

	if( ( restrictops & opflag )
			|| ( exopflag && ( restrictops & exopflag ) ) ) {
		if( ( restrictops & SLAP_RESTRICT_OP_MASK) == SLAP_RESTRICT_OP_READS ) {
			rs->sr_text = "read operations restricted";
		} else if ( restrictops & exopflag ) {
			rs->sr_text = "extended operation restricted";
		} else {
			rs->sr_text = "operation restricted";
		}
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		return rs->sr_err;
 	}

	rs->sr_err = LDAP_SUCCESS;
	return rs->sr_err;
}

int backend_check_referrals( Operation *op, SlapReply *rs )
{
	rs->sr_err = LDAP_SUCCESS;

	if( op->o_bd->be_chk_referrals ) {
		rs->sr_err = op->o_bd->be_chk_referrals( op, rs );

		if( rs->sr_err != LDAP_SUCCESS && rs->sr_err != LDAP_REFERRAL ) {
			send_ldap_result( op, rs );
		}
	}

	return rs->sr_err;
}

int
be_entry_get_rw(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **e )
{
	int rc;

	*e = NULL;

	if (op->o_bd == NULL) {
		rc = LDAP_NO_SUCH_OBJECT;
	} else if ( op->o_bd->be_fetch ) {
		rc = ( op->o_bd->be_fetch )( op, ndn,
			oc, at, rw, e );
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}
	return rc;
}

int 
backend_group(
	Operation *op,
	Entry	*target,
	struct berval *gr_ndn,
	struct berval *op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at )
{
	Entry *e;
	Attribute *a;
	int rc;
	GroupAssertion *g;
	Backend *be = op->o_bd;

	if ( op->o_abandon ) return SLAPD_ABANDON;

	op->o_bd = select_backend( gr_ndn, 0, 0 );

	for (g = op->o_groups; g; g=g->ga_next) {
		if (g->ga_be != op->o_bd || g->ga_oc != group_oc ||
			g->ga_at != group_at || g->ga_len != gr_ndn->bv_len)
			continue;
		if (strcmp( g->ga_ndn, gr_ndn->bv_val ) == 0)
			break;
	}

	if (g) {
		rc = g->ga_res;
		goto done;
	}

	if ( target && dn_match( &target->e_nname, gr_ndn ) ) {
		e = target;
		rc = 0;
	} else {
		rc = be_entry_get_rw(op, gr_ndn, group_oc, group_at, 0, &e );
	}
	if ( e ) {
		a = attr_find( e->e_attrs, group_at );
		if ( a ) {
			/* If the attribute is a subtype of labeledURI, treat this as
			 * a dynamic group ala groupOfURLs
			 */
			if (is_at_subtype( group_at->ad_type,
				slap_schema.si_ad_labeledURI->ad_type ) )
			{
				int i;
				LDAPURLDesc *ludp;
				struct berval bv, nbase;
				Filter *filter;
				Entry *user;
				Backend *b2 = op->o_bd;

				if ( target && dn_match( &target->e_nname, op_ndn ) ) {
					user = target;
				} else {
					op->o_bd = select_backend( op_ndn, 0, 0 );
					rc = be_entry_get_rw(op, op_ndn, NULL, NULL, 0, &user );
				}
				
				if ( rc == 0 ) {
					rc = 1;
					for (i=0; a->a_vals[i].bv_val; i++) {
						if ( ldap_url_parse( a->a_vals[i].bv_val, &ludp ) !=
							LDAP_SUCCESS )
						{
							continue;
						}
						nbase.bv_val = NULL;
						/* host part must be empty */
						/* attrs and extensions parts must be empty */
						if (( ludp->lud_host && *ludp->lud_host ) ||
							ludp->lud_attrs || ludp->lud_exts )
						{
							goto loopit;
						}
						ber_str2bv( ludp->lud_dn, 0, 0, &bv );
						if ( dnNormalize( 0, NULL, NULL, &bv, &nbase,
							op->o_tmpmemctx ) != LDAP_SUCCESS )
						{
							goto loopit;
						}
						switch(ludp->lud_scope) {
						case LDAP_SCOPE_BASE:
							if ( !dn_match( &nbase, op_ndn )) goto loopit;
							break;
						case LDAP_SCOPE_ONELEVEL:
							dnParent(op_ndn, &bv );
							if ( !dn_match( &nbase, &bv )) goto loopit;
							break;
						case LDAP_SCOPE_SUBTREE:
							if ( !dnIsSuffix( op_ndn, &nbase )) goto loopit;
							break;
#ifdef LDAP_SCOPE_SUBORDINATE
						case LDAP_SCOPE_SUBORDINATE:
							if ( dn_match( &nbase, op_ndn ) &&
								!dnIsSuffix(op_ndn, &nbase ))
							{
								goto loopit;
							}
#endif
						}
						filter = str2filter_x( op, ludp->lud_filter );
						if ( filter ) {
							if ( test_filter( NULL, user, filter ) ==
								LDAP_COMPARE_TRUE )
							{
								rc = 0;
							}
							filter_free_x( op, filter );
						}
loopit:
						ldap_free_urldesc( ludp );
						if ( nbase.bv_val ) {
							op->o_tmpfree( nbase.bv_val, op->o_tmpmemctx );
						}
						if ( rc == 0 ) break;
					}
					if ( user != target ) {
						be_entry_release_r( op, user );
					}
				}
				op->o_bd = b2;
			} else {
				rc = value_find_ex( group_at,
				SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
				SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
				a->a_nvals, op_ndn, op->o_tmpmemctx );
			}
		} else {
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		}
		if (e != target ) {
			be_entry_release_r( op, e );
		}
	} else {
		rc = LDAP_NO_SUCH_OBJECT;
	}

	if ( op->o_tag != LDAP_REQ_BIND && !op->o_do_not_cache ) {
		g = op->o_tmpalloc(sizeof(GroupAssertion) + gr_ndn->bv_len,
			op->o_tmpmemctx);
		g->ga_be = op->o_bd;
		g->ga_oc = group_oc;
		g->ga_at = group_at;
		g->ga_res = rc;
		g->ga_len = gr_ndn->bv_len;
		strcpy(g->ga_ndn, gr_ndn->bv_val);
		g->ga_next = op->o_groups;
		op->o_groups = g;
	}
done:
	op->o_bd = be;
	return rc;
}

int 
backend_attribute(
	Operation *op,
	Entry	*target,
	struct berval	*edn,
	AttributeDescription *entry_at,
	BerVarray *vals )
{
	Entry *e;
	Attribute *a;
	int i, j, rc = LDAP_SUCCESS;
	AccessControlState acl_state = ACL_STATE_INIT;
	Backend *be = op->o_bd;

	op->o_bd = select_backend( edn, 0, 0 );

	if ( target && dn_match( &target->e_nname, edn ) ) {
		e = target;
	} else {
		rc = be_entry_get_rw(op, edn, NULL, entry_at, 0, &e );
	} 

	if ( e ) {
		a = attr_find( e->e_attrs, entry_at );
		if ( a ) {
			BerVarray v;

			if ( op->o_conn && access_allowed( op,
				e, entry_at, NULL, ACL_AUTH,
				&acl_state ) == 0 ) {
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto freeit;
			}

			for ( i=0; a->a_vals[i].bv_val; i++ ) ;
			
			v = op->o_tmpalloc( sizeof(struct berval) * (i+1),
				op->o_tmpmemctx );
			for ( i=0,j=0; a->a_vals[i].bv_val; i++ ) {
				if ( op->o_conn && access_allowed( op,
					e, entry_at,
					&a->a_nvals[i],
					ACL_AUTH, &acl_state ) == 0 ) {
					continue;
				}
				ber_dupbv_x( &v[j],
					&a->a_nvals[i], op->o_tmpmemctx );
				if (v[j].bv_val ) j++;
			}
			if (j == 0) {
				op->o_tmpfree( v, op->o_tmpmemctx );
				*vals = NULL;
				rc = LDAP_INSUFFICIENT_ACCESS;
			} else {
				v[j].bv_val = NULL;
				v[j].bv_len = 0;
				*vals = v;
				rc = LDAP_SUCCESS;
			}
		}
freeit:		if (e != target ) {
			be_entry_release_r( op, e );
		}
	}

	op->o_bd = be;
	return rc;
}

int backend_operational(
	Operation *op,
	SlapReply *rs )
{
	Attribute	**ap;
	int		rc = 0;

	for ( ap = &rs->sr_operational_attrs; *ap; ap = &(*ap)->a_next )
		/* just count them */ ;

	/*
	 * If operational attributes (allegedly) are required, 
	 * and the backend supports specific operational attributes, 
	 * add them to the attribute list
	 */
	if ( SLAP_OPATTRS( rs->sr_attr_flags ) || ( op->ors_attrs &&
		ad_inlist( slap_schema.si_ad_subschemaSubentry, op->ors_attrs )) ) {
		*ap = slap_operational_subschemaSubentry( op->o_bd );

		ap = &(*ap)->a_next;
	}

	if ( ( SLAP_OPATTRS( rs->sr_attr_flags ) || op->ors_attrs ) && op->o_bd &&
		op->o_bd->be_operational != NULL )
	{
		Attribute	*a;
		
		a = rs->sr_operational_attrs;
		rs->sr_operational_attrs = NULL;
		rc = op->o_bd->be_operational( op, rs );
		*ap = rs->sr_operational_attrs;
		if ( a != NULL ) {
			rs->sr_operational_attrs = a;
		}

		for ( ; *ap; ap = &(*ap)->a_next )
			/* just count them */ ;
	}

	return rc;
}


/* backend.c - routines for dealing with back-end databases */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2005 The OpenLDAP Foundation.
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

static void init_group_pblock( Operation *op, Entry *target,
	Entry *e, struct berval *op_ndn, AttributeDescription *group_at );
static int call_group_preop_plugins( Operation *op );
static void call_group_postop_plugins( Operation *op );
#endif /* LDAP_SLAPI */

/*
 * If a module is configured as dynamic, its header should not
 * get included into slapd. While this is a general rule and does
 * not have much of an effect in UNIX, this rule should be adhered
 * to for Windows, where dynamic object code should not be implicitly
 * imported into slapd without appropriate __declspec(dllimport) directives.
 */

int			nBackendInfo = 0;
BackendInfo		*backendInfo = NULL;

int			nBackendDB = 0; 
BackendDB		*backendDB = NULL;

static int
backend_init_controls( BackendInfo *bi )
{
	if ( bi->bi_controls ) {
		int	i;

		for ( i = 0; bi->bi_controls[ i ]; i++ ) {
			int	cid;

			if ( slap_find_control_id( bi->bi_controls[ i ], &cid )
					== LDAP_CONTROL_NOT_FOUND )
			{
				if ( !( slapMode & SLAP_TOOL_MODE ) ) {
					assert( 0 );
				}

				return -1;
			}

			bi->bi_ctrls[ cid ] = 1;
		}
	}

	return 0;
}

int backend_init(void)
{
	int rc = -1;

	if((nBackendInfo != 0) || (backendInfo != NULL)) {
		/* already initialized */
		Debug( LDAP_DEBUG_ANY,
			"backend_init: already initialized\n", 0, 0, 0 );
		return -1;
	}

	for( ;
		slap_binfo[nBackendInfo].bi_type != NULL;
		nBackendInfo++ )
	{
		assert( slap_binfo[nBackendInfo].bi_init );

		rc = slap_binfo[nBackendInfo].bi_init( &slap_binfo[nBackendInfo] );

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_init: initialized for type \"%s\"\n",
				slap_binfo[nBackendInfo].bi_type, 0, 0 );
			/* destroy those we've already inited */
			for( nBackendInfo--;
				nBackendInfo >= 0 ;
				nBackendInfo-- )
			{ 
				if ( slap_binfo[nBackendInfo].bi_destroy ) {
					slap_binfo[nBackendInfo].bi_destroy(
						&slap_binfo[nBackendInfo] );
				}
			}
			return rc;
		}
	}

	if ( nBackendInfo > 0) {
		backendInfo = slap_binfo;
		return 0;
	}

#ifdef SLAPD_MODULES	
	return 0;
#else

	Debug( LDAP_DEBUG_ANY,
		"backend_init: failed\n",
		0, 0, 0 );

	return rc;
#endif /* SLAPD_MODULES */
}

int backend_add(BackendInfo *aBackendInfo)
{
	int rc = 0;

	if ( aBackendInfo->bi_init == NULL ) {
		Debug( LDAP_DEBUG_ANY, "backend_add: "
			"backend type \"%s\" does not have the (mandatory)init function\n",
			aBackendInfo->bi_type, 0, 0 );
		return -1;
	}

	rc = aBackendInfo->bi_init(aBackendInfo);
	if ( rc != 0) {
		Debug( LDAP_DEBUG_ANY,
			"backend_add:  initialization for type \"%s\" failed\n",
			aBackendInfo->bi_type, 0, 0 );
		return rc;
	}

	(void)backend_init_controls( aBackendInfo );

	/* now add the backend type to the Backend Info List */
	{
		BackendInfo *newBackendInfo = 0;

		/* if backendInfo == slap_binfo no deallocation of old backendInfo */
		if (backendInfo == slap_binfo) {
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

static int
backend_set_controls( BackendDB *be )
{
	BackendInfo	*bi = be->bd_info;

	/* back-relay takes care of itself; so may do other */
	if ( overlay_is_over( be ) ) {
		bi = ((slap_overinfo *)be->bd_info->bi_private)->oi_orig;
	}

	if ( bi->bi_controls ) {
		if ( be->be_ctrls[ SLAP_MAX_CIDS ] == 0 ) {
			AC_MEMCPY( be->be_ctrls, bi->bi_ctrls,
					sizeof( be->be_ctrls ) );
			be->be_ctrls[ SLAP_MAX_CIDS ] = 1;
			
		} else {
			int	i;
			
			for ( i = 0; i < SLAP_MAX_CIDS; i++ ) {
				if ( bi->bi_ctrls[ i ] ) {
					be->be_ctrls[ i ] = bi->bi_ctrls[ i ];
				}
			}
		}

	}

	return 0;
}

/* startup a specific backend database */
int backend_startup_one(Backend *be)
{
	int		rc = 0;

	assert( be );

	be->be_pending_csn_list = (struct be_pcl *)
		ch_calloc( 1, sizeof( struct be_pcl ));

	LDAP_TAILQ_INIT( be->be_pending_csn_list );

	Debug( LDAP_DEBUG_TRACE,
		"backend_startup_one: starting \"%s\"\n",
		be->be_suffix ? be->be_suffix[0].bv_val : "(unknown)",
		0, 0 );

	/* set database controls */
	(void)backend_set_controls( be );

	if ( be->bd_info->bi_db_open ) {
		rc = be->bd_info->bi_db_open( be );
		if ( rc == 0 ) {
			(void)backend_set_controls( be );

		} else {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup_one: bi_db_open failed! (%d)\n",
				rc, 0, 0 );
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
		Debug( LDAP_DEBUG_ANY,
			"backend_startup: %d databases to startup.\n",
			nBackendDB, 0, 0 );
		return 1;
	}

	if(be != NULL) {
		if ( be->bd_info->bi_open ) {
			rc = be->bd_info->bi_open( be->bd_info );
			if ( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_open failed!\n",
					0, 0, 0 );

				return rc;
			}
		}

		return backend_startup_one( be );
	}

	/* open frontend, if required */
	if ( frontendDB->bd_info->bi_db_open ) {
		rc = frontendDB->bd_info->bi_db_open( frontendDB );
		if ( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_db_open(frontend) failed! (%d)\n",
				rc, 0, 0 );
			return rc;
		}
	}

	/* open each backend type */
	for( i = 0; i < nBackendInfo; i++ ) {
		if( backendInfo[i].bi_nDB == 0) {
			/* no database of this type, don't open */
			continue;
		}

		if( backendInfo[i].bi_open ) {
			rc = backendInfo[i].bi_open( &backendInfo[i] );
			if ( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_open %d failed!\n",
					i, 0, 0 );
				return rc;
			}
		}

		(void)backend_init_controls( &backendInfo[i] );
	}

	ldap_pvt_thread_mutex_init( &slapd_rq.rq_mutex );
	LDAP_STAILQ_INIT( &slapd_rq.task_list );
	LDAP_STAILQ_INIT( &slapd_rq.run_list );

	/* open each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		if ( backendDB[i].be_suffix == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: warning, database %d (%s) "
				"has no suffix\n",
				i, backendDB[i].bd_info->bi_type, 0 );
		}
		/* append global access controls */
		acl_append( &backendDB[i].be_acl, frontendDB->be_acl );

		rc = backend_startup_one( &backendDB[i] );

		if ( rc ) return rc;


		if ( backendDB[i].be_syncinfo ) {
			syncinfo_t *si;

			if ( !( backendDB[i].be_search && backendDB[i].be_add &&
				backendDB[i].be_modify && backendDB[i].be_delete )) {
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: database(%d) does not support "
					"operations required for syncrepl", i, 0, 0 );
				continue;
			}

			{
				si = backendDB[i].be_syncinfo;
				si->si_be = &backendDB[i];
				init_syncrepl( si );
				ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
				ldap_pvt_runqueue_insert( &slapd_rq,
						si->si_interval, do_syncrepl, (void *) si );
				ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );
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
			Debug( LDAP_DEBUG_ANY,
				"backend_close: bi_db_close %s failed!\n",
				backendDB[i].be_type, 0, 0 );
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

	/* close frontend, if required */
	if ( frontendDB->bd_info->bi_db_close ) {
		rc = frontendDB->bd_info->bi_db_close ( frontendDB );
		if ( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_db_close(frontend) failed! (%d)\n",
				rc, 0, 0 );
		}
	}

	return 0;
}

int backend_destroy(void)
{
	int i;
	BackendDB *bd;
	struct slap_csn_entry *csne;

	/* destroy each backend database */
	for( i = 0, bd = backendDB; i < nBackendDB; i++, bd++ ) {

		if ( bd->be_syncinfo ) {
			syncinfo_free( bd->be_syncinfo );
		}

		if ( bd->be_pending_csn_list ) {
			csne = LDAP_TAILQ_FIRST( bd->be_pending_csn_list );
			while ( csne ) {
				struct slap_csn_entry *tmp_csne = csne;

				LDAP_TAILQ_REMOVE( bd->be_pending_csn_list, csne, ce_csn_link );
				ch_free( csne->ce_csn.bv_val );
				csne = LDAP_TAILQ_NEXT( csne, ce_csn_link );
				ch_free( tmp_csne );
			}
		}
		
		if ( bd->bd_info->bi_db_destroy ) {
			bd->bd_info->bi_db_destroy( bd );
		}
		ber_bvarray_free( bd->be_suffix );
		ber_bvarray_free( bd->be_nsuffix );
		if ( !BER_BVISNULL( &bd->be_rootdn ) ) {
			free( bd->be_rootdn.bv_val );
		}
		if ( !BER_BVISNULL( &bd->be_rootndn ) ) {
			free( bd->be_rootndn.bv_val );
		}
		if ( !BER_BVISNULL( &bd->be_rootpw ) ) {
			free( bd->be_rootpw.bv_val );
		}
		acl_destroy( bd->be_acl, frontendDB->be_acl );
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
	if (backendInfo != slap_binfo) {
	   free(backendInfo);
	}
#endif /* SLAPD_MODULES */

	nBackendInfo = 0;
	backendInfo = NULL;

	/* destroy frontend database */
	bd = frontendDB;
	if ( bd ) {
		if ( bd->bd_info->bi_db_destroy ) {
			bd->bd_info->bi_db_destroy( bd );
		}
		ber_bvarray_free( bd->be_suffix );
		ber_bvarray_free( bd->be_nsuffix );
		if ( !BER_BVISNULL( &bd->be_rootdn ) ) {
			free( bd->be_rootdn.bv_val );
		}
		if ( !BER_BVISNULL( &bd->be_rootndn ) ) {
			free( bd->be_rootndn.bv_val );
		}
		if ( !BER_BVISNULL( &bd->be_rootpw ) ) {
			free( bd->be_rootpw.bv_val );
		}
		acl_destroy( bd->be_acl, frontendDB->be_acl );
	}

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

	be = backendDB;

	backendDB = (BackendDB *) ch_realloc(
			(char *) backendDB,
		    (nBackendDB + 1) * sizeof(Backend) );

	memset( &backendDB[nbackends], '\0', sizeof(Backend) );

	/* did realloc move our table? if so, fix up dependent pointers */
	if ( be != backendDB ) {
		int i;
		for ( i=0, be=backendDB; i<nbackends; i++, be++ ) {
			be->be_pcl_mutexp = &be->be_pcl_mutex;
		}
	}

	be = &backends[nbackends++];

	be->bd_info = bi;

	be->be_def_limit = frontendDB->be_def_limit;
	be->be_dfltaccess = frontendDB->be_dfltaccess;

	be->be_restrictops = frontendDB->be_restrictops;
	be->be_requires = frontendDB->be_requires;
	be->be_ssf_set = frontendDB->be_ssf_set;

	be->be_pcl_mutexp = &be->be_pcl_mutex;
	ldap_pvt_thread_mutex_init( be->be_pcl_mutexp );

 	/* assign a default depth limit for alias deref */
	be->be_max_deref_depth = SLAPD_DEFAULT_MAXDEREFDEPTH; 

	if ( bi->bi_db_init ) {
		rc = bi->bi_db_init( be );
	}

	if ( rc != 0 ) {
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

	if ( frontendDB->bd_info->bi_db_close ) {
		(*frontendDB->bd_info->bi_db_close)( frontendDB );
	}

}

Backend *
select_backend(
	struct berval * dn,
	int manageDSAit,
	int noSubs )
{
	int		i, j;
	ber_len_t	len, dnlen = dn->bv_len;
	Backend		*be = NULL;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_nsuffix == NULL ) {
			continue;
		}

		for ( j = 0; !BER_BVISNULL( &backends[i].be_nsuffix[j] ); j++ )
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

	if ( be->be_nsuffix == NULL ) {
		return 0;
	}

	for ( i = 0; !BER_BVISNULL( &be->be_nsuffix[i] ); i++ ) {
		if ( bvmatch( &be->be_nsuffix[i], bvsuffix ) ) {
			return 1;
		}
	}

	return 0;
}

int
be_isroot_dn( Backend *be, struct berval *ndn )
{
	if ( BER_BVISEMPTY( ndn ) || BER_BVISEMPTY( &be->be_rootndn ) ) {
		return 0;
	}

	return dn_match( &be->be_rootndn, ndn );
}

int
be_slurp_update( Operation *op )
{
	return ( SLAP_SLURP_SHADOW( op->o_bd ) &&
		be_isupdate_dn( op->o_bd, &op->o_ndn ) );
}

int
be_shadow_update( Operation *op )
{
	return ( SLAP_SYNC_SHADOW( op->o_bd ) ||
		( SLAP_SHADOW( op->o_bd ) && be_isupdate_dn( op->o_bd, &op->o_ndn ) ) );
}

int
be_isupdate_dn( Backend *be, struct berval *ndn )
{
	if ( BER_BVISEMPTY( ndn ) || BER_BVISEMPTY( &be->be_update_ndn ) ) {
		return 0;
	}

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

	if ( BER_BVISEMPTY( &op->o_bd->be_rootpw ) ) {
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
				Debug(LDAP_DEBUG_TRACE,
					"do_bind: Unbind preoperation plugin failed\n",
					0, 0, 0);
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
			Debug(LDAP_DEBUG_TRACE,
				"do_unbind: Unbind postoperation plugins failed\n",
				0, 0, 0);
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

int
backend_check_controls(
	Operation *op,
	SlapReply *rs )
{
	LDAPControl **ctrls = op->o_ctrls;
	rs->sr_err = LDAP_SUCCESS;

	if( ctrls ) {
		for( ; *ctrls != NULL ; ctrls++ ) {
			int cid;

			switch ( slap_global_control( op, (*ctrls)->ldctl_oid, &cid ) ) {
			case LDAP_CONTROL_NOT_FOUND:
				/* unrecognized control */ 
				if ( (*ctrls)->ldctl_iscritical ) {
					/* should not be reachable */ 
					Debug( LDAP_DEBUG_ANY,
						"backend_check_controls: unrecognized control: %s\n",
						(*ctrls)->ldctl_oid, 0, 0 );
					assert( 0 );
				}
				break;

			case LDAP_COMPARE_FALSE:
				if ( !op->o_bd->be_ctrls[ cid ] )
				{
					/* Per RFC 2251 (and LDAPBIS discussions), if the control
					 * is recognized and appropriate for the operation (which
					 * we've already verified), then the server should make
					 * use of the control when performing the operation.
					 * 
					 * Here we find that operation extended by the control
					 * is not unavailable in a particular context, hence the
					 * return of unwillingToPerform.
					 */
					rs->sr_text = "control unavailable in context";
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					goto done;
				}
				break;

			case LDAP_COMPARE_TRUE:
				break;

			default:
				/* unreachable */
				rs->sr_text = "unable to check control";
				rs->sr_err = LDAP_OTHER;
				goto done;
			}
		}
	}

done:;
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

	if ( op->o_bd ) {
		int	rc = SLAP_CB_CONTINUE;

		if ( op->o_bd->be_chk_controls ) {
			rc = ( *op->o_bd->be_chk_controls )( op, rs );
		}

		if ( rc == SLAP_CB_CONTINUE ) {
			rc = backend_check_controls( op, rs );
		}

		if ( rc != LDAP_SUCCESS ) {
			return rs->sr_err;
		}

		restrictops = op->o_bd->be_restrictops;
		requires = op->o_bd->be_requires;
		ssf = &op->o_bd->be_ssf_set;

	} else {
		restrictops = frontendDB->be_restrictops;
		requires = frontendDB->be_requires;
		ssf = &frontendDB->be_ssf_set;
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
				BER_BVISEMPTY( &op->o_ndn ) )
			{
				rs->sr_text = "modifications require authentication";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}

#ifdef SLAP_X_LISTENER_MOD
			if ( op->o_conn->c_listener && ! ( op->o_conn->c_listener->sl_perms & ( !BER_BVISEMPTY( &op->o_ndn ) ? S_IWUSR : S_IWOTH ) ) ) {
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
				|| BER_BVISEMPTY( &op->o_dn ) )
			{
				rs->sr_text = "strong(er) authentication required";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}
		}

		if( requires & SLAP_REQUIRE_SASL ) {
			if( op->o_authtype != LDAP_AUTH_SASL || BER_BVISEMPTY( &op->o_dn ) ) {
				rs->sr_text = "SASL authentication required";
				rs->sr_err = LDAP_STRONG_AUTH_REQUIRED;
				return rs->sr_err;
			}
		}
			
		if( requires & SLAP_REQUIRE_AUTHC ) {
			if( BER_BVISEMPTY( &op->o_dn ) ) {
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
		if ( !starttls && BER_BVISEMPTY( &op->o_dn ) ) {
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
					( !BER_BVISEMPTY( &op->o_dn ) ? S_IRUSR : S_IROTH )))
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

	for ( g = op->o_groups; g; g = g->ga_next ) {
		if ( g->ga_be != op->o_bd || g->ga_oc != group_oc ||
			g->ga_at != group_at || g->ga_len != gr_ndn->bv_len )
		{
			continue;
		}
		if ( strcmp( g->ga_ndn, gr_ndn->bv_val ) == 0 ) {
			break;
		}
	}

	if ( g ) {
		rc = g->ga_res;
		goto done;
	}

	if ( target && dn_match( &target->e_nname, gr_ndn ) ) {
		e = target;
		rc = 0;
	} else {
		rc = be_entry_get_rw( op, gr_ndn, group_oc, group_at, 0, &e );
	}
	if ( e ) {
#ifdef LDAP_SLAPI
		if ( op->o_pb != NULL ) {
			init_group_pblock( op, target, e, op_ndn, group_at );

			rc = call_group_preop_plugins( op );
			if ( rc == LDAP_SUCCESS ) {
				goto done;
			}
		}
#endif /* LDAP_SLAPI */

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
					for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
						if ( ldap_url_parse( a->a_vals[i].bv_val, &ludp ) !=
							LDAP_URL_SUCCESS )
						{
							continue;
						}
						BER_BVZERO( &nbase );
						/* host part must be empty */
						/* attrs and extensions parts must be empty */
						if ( ( ludp->lud_host && *ludp->lud_host ) ||
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
						switch ( ludp->lud_scope ) {
						case LDAP_SCOPE_BASE:
							if ( !dn_match( &nbase, op_ndn ) ) {
								goto loopit;
							}
							break;
						case LDAP_SCOPE_ONELEVEL:
							dnParent( op_ndn, &bv );
							if ( !dn_match( &nbase, &bv ) ) {
								goto loopit;
							}
							break;
						case LDAP_SCOPE_SUBTREE:
							if ( !dnIsSuffix( op_ndn, &nbase ) ) {
								goto loopit;
							}
							break;
#ifdef LDAP_SCOPE_SUBORDINATE
						case LDAP_SCOPE_SUBORDINATE:
							if ( dn_match( &nbase, op_ndn ) ||
								!dnIsSuffix( op_ndn, &nbase ) )
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
						if ( !BER_BVISNULL( &nbase ) ) {
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

#ifdef LDAP_SLAPI
	if ( op->o_pb ) call_group_postop_plugins( op );
#endif /* LDAP_SLAPI */

	if ( op->o_tag != LDAP_REQ_BIND && !op->o_do_not_cache ) {
		g = op->o_tmpalloc( sizeof( GroupAssertion ) + gr_ndn->bv_len,
			op->o_tmpmemctx );
		g->ga_be = op->o_bd;
		g->ga_oc = group_oc;
		g->ga_at = group_at;
		g->ga_res = rc;
		g->ga_len = gr_ndn->bv_len;
		strcpy( g->ga_ndn, gr_ndn->bv_val );
		g->ga_next = op->o_groups;
		op->o_groups = g;
	}
done:
	op->o_bd = be;
	return rc;
}

#ifdef LDAP_SLAPI
static int backend_compute_output_attr(computed_attr_context *c, Slapi_Attr *a, Slapi_Entry *e)
{
	BerVarray v;
	int rc;
	BerVarray *vals = (BerVarray *)c->cac_private;
	Operation *op = NULL;
	int i, j;

	slapi_pblock_get( c->cac_pb, SLAPI_OPERATION, &op );
	if ( op == NULL ) {
		return 1;
	}

	if ( op->o_conn && access_allowed( op,
		e, a->a_desc, NULL, ACL_AUTH,
		&c->cac_acl_state ) == 0 ) {
		return 1;
	}

	for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) ;
			
	v = op->o_tmpalloc( sizeof(struct berval) * (i+1),
		op->o_tmpmemctx );
	for ( i = 0, j = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
		if ( op->o_conn && access_allowed( op,
			e, a->a_desc,
			&a->a_nvals[i],
			ACL_AUTH, &c->cac_acl_state ) == 0 ) {
			continue;
		}
		ber_dupbv_x( &v[j],
			&a->a_nvals[i], op->o_tmpmemctx );
		if ( !BER_BVISNULL( &v[j] ) ) {
			j++;
		}
	}

	if ( j == 0 ) {
		op->o_tmpfree( v, op->o_tmpmemctx );
		*vals = NULL;
		rc = 1;
	} else {
		BER_BVZERO( &v[j] );
		*vals = v;
		rc = 0;
	}

	return rc;
}
#endif /* LDAP_SLAPI */

int 
backend_attribute(
	Operation *op,
	Entry	*target,
	struct berval	*edn,
	AttributeDescription *entry_at,
	BerVarray *vals,
	slap_access_t access )
{
	Entry			*e = NULL;
	Attribute		*a = NULL;
	int			freeattr = 0, i, j, rc = LDAP_SUCCESS;
	AccessControlState	acl_state = ACL_STATE_INIT;
	Backend			*be = op->o_bd;

	op->o_bd = select_backend( edn, 0, 0 );

	if ( target && dn_match( &target->e_nname, edn ) ) {
		e = target;

	} else {
		rc = be_entry_get_rw( op, edn, NULL, entry_at, 0, &e );
	} 

	if ( e ) {
		a = attr_find( e->e_attrs, entry_at );
		if ( a == NULL ) {
			SlapReply	rs = { 0 };
			AttributeName	anlist[ 2 ];

			anlist[ 0 ].an_name = entry_at->ad_cname;
			anlist[ 0 ].an_desc = entry_at;
			BER_BVZERO( &anlist[ 1 ].an_name );
			rs.sr_attrs = anlist;
			
 			/* NOTE: backend_operational() is also called
 			 * when returning results, so it's supposed
 			 * to do no harm to entries */
 			rs.sr_entry = e;
  			rc = backend_operational( op, &rs );
 			rs.sr_entry = NULL;
 
			if ( rc == LDAP_SUCCESS ) {
				if ( rs.sr_operational_attrs ) {
					freeattr = 1;
					a = rs.sr_operational_attrs;

				} else {
					rc = LDAP_NO_SUCH_ATTRIBUTE;
				}
			}
		}

		if ( a ) {
			BerVarray v;

			if ( op->o_conn && access > ACL_NONE && access_allowed( op,
				e, entry_at, NULL, access,
				&acl_state ) == 0 ) {
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto freeit;
			}

			for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ )
				;
			
			v = op->o_tmpalloc( sizeof(struct berval) * ( i + 1 ),
				op->o_tmpmemctx );
			for ( i = 0,j = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ )
			{
				if ( op->o_conn && access > ACL_NONE && 
						access_allowed( op, e,
							entry_at,
							&a->a_nvals[i],
							access,
							&acl_state ) == 0 )
				{
					continue;
				}
				ber_dupbv_x( &v[j], &a->a_nvals[i],
						op->o_tmpmemctx );
				if ( !BER_BVISNULL( &v[j] ) ) {
					j++;
				}
			}
			if ( j == 0 ) {
				op->o_tmpfree( v, op->o_tmpmemctx );
				*vals = NULL;
				rc = LDAP_INSUFFICIENT_ACCESS;

			} else {
				BER_BVZERO( &v[j] );
				*vals = v;
				rc = LDAP_SUCCESS;
			}
		}
#ifdef LDAP_SLAPI
		else if ( op->o_pb ) {
			/* try any computed attributes */
			computed_attr_context	ctx;

			slapi_int_pblock_set_operation( op->o_pb, op );

			ctx.cac_pb = op->o_pb;
			ctx.cac_attrs = NULL;
			ctx.cac_userattrs = 0;
			ctx.cac_opattrs = 0;
			ctx.cac_acl_state = acl_state;
			ctx.cac_private = (void *)vals;

			rc = compute_evaluator( &ctx, entry_at->ad_cname.bv_val, e, backend_compute_output_attr );
			if ( rc == 1 ) {
				rc = LDAP_INSUFFICIENT_ACCESS;

			} else {
				rc = LDAP_SUCCESS;
			}
		}
#endif /* LDAP_SLAPI */
freeit:		if ( e != target ) {
			be_entry_release_r( op, e );
		}
		if ( freeattr ) {
			attr_free( a );
		}
	}

	op->o_bd = be;
	return rc;
}

#ifdef LDAP_SLAPI
static int backend_compute_output_attr_access(computed_attr_context *c, Slapi_Attr *a, Slapi_Entry *e)
{
	struct berval	*nval = (struct berval *)c->cac_private;
	Operation	*op = NULL;

	slapi_pblock_get( c->cac_pb, SLAPI_OPERATION, &op );
	if ( op == NULL ) {
		return 1;
	}

	return access_allowed( op, e, a->a_desc, nval, ACL_AUTH, NULL ) == 0;
}
#endif /* LDAP_SLAPI */

int 
backend_access(
	Operation		*op,
	Entry			*target,
	struct berval		*edn,
	AttributeDescription	*entry_at,
	struct berval		*nval,
	slap_access_t		access,
	slap_mask_t		*mask )
{
	Entry		*e = NULL;
	int		rc = LDAP_INSUFFICIENT_ACCESS;
	Backend		*be = op->o_bd;

	/* pedantic */
	assert( op );
	assert( op->o_conn );
	assert( edn );
	assert( access > ACL_NONE );

	op->o_bd = select_backend( edn, 0, 0 );

	if ( target && dn_match( &target->e_nname, edn ) ) {
		e = target;

	} else {
		rc = be_entry_get_rw( op, edn, NULL, entry_at, 0, &e );
	} 

	if ( e ) {
		Attribute	*a = NULL;
		int		freeattr = 0;

		if ( entry_at == NULL ) {
			entry_at = slap_schema.si_ad_entry;
		}

		if ( entry_at == slap_schema.si_ad_entry || entry_at == slap_schema.si_ad_children )
		{
			if ( access_allowed_mask( op, e, entry_at,
					NULL, access, NULL, mask ) == 0 )
			{
				rc = LDAP_INSUFFICIENT_ACCESS;

			} else {
				rc = LDAP_SUCCESS;
			}

		} else {
			a = attr_find( e->e_attrs, entry_at );
			if ( a == NULL ) {
				SlapReply	rs = { 0 };
				AttributeName	anlist[ 2 ];

				anlist[ 0 ].an_name = entry_at->ad_cname;
				anlist[ 0 ].an_desc = entry_at;
				BER_BVZERO( &anlist[ 1 ].an_name );
				rs.sr_attrs = anlist;
			
				rs.sr_attr_flags = slap_attr_flags( rs.sr_attrs );

				/* NOTE: backend_operational() is also called
				 * when returning results, so it's supposed
				 * to do no harm to entries */
				rs.sr_entry = e;
				rc = backend_operational( op, &rs );
				rs.sr_entry = NULL;

				if ( rc == LDAP_SUCCESS ) {
					if ( rs.sr_operational_attrs ) {
						freeattr = 1;
						a = rs.sr_operational_attrs;

					} else {
						rc = LDAP_NO_SUCH_OBJECT;
					}
				}
			}

			if ( a ) {
				if ( access_allowed_mask( op, e, entry_at,
						nval, access, NULL, mask ) == 0 )
				{
					rc = LDAP_INSUFFICIENT_ACCESS;
					goto freeit;
				}
				rc = LDAP_SUCCESS;
			}
#ifdef LDAP_SLAPI
			else if ( op->o_pb ) {
				/* try any computed attributes */
				computed_attr_context	ctx;

				slapi_int_pblock_set_operation( op->o_pb, op );

				ctx.cac_pb = op->o_pb;
				ctx.cac_attrs = NULL;
				ctx.cac_userattrs = 0;
				ctx.cac_opattrs = 0;
				ctx.cac_private = (void *)nval;

				rc = compute_evaluator( &ctx, entry_at->ad_cname.bv_val, e, backend_compute_output_attr_access );
				if ( rc == 1 ) {
					rc = LDAP_INSUFFICIENT_ACCESS;

				} else {
					rc = LDAP_SUCCESS;
				}
			}
#endif /* LDAP_SLAPI */
		}
freeit:		if ( e != target ) {
			be_entry_release_r( op, e );
		}
		if ( freeattr ) {
			attr_free( a );
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
	BackendDB	*be_orig;

	for ( ap = &rs->sr_operational_attrs; *ap; ap = &(*ap)->a_next )
		/* just count them */ ;

	/*
	 * If operational attributes (allegedly) are required, 
	 * and the backend supports specific operational attributes, 
	 * add them to the attribute list
	 */
	if ( SLAP_OPATTRS( rs->sr_attr_flags ) || ( rs->sr_attrs &&
		ad_inlist( slap_schema.si_ad_entryDN, rs->sr_attrs )))
	{
		*ap = slap_operational_entryDN( rs->sr_entry );
		ap = &(*ap)->a_next;
	}

	if ( SLAP_OPATTRS( rs->sr_attr_flags ) || ( rs->sr_attrs &&
		ad_inlist( slap_schema.si_ad_subschemaSubentry, rs->sr_attrs )))
	{
		*ap = slap_operational_subschemaSubentry( op->o_bd );
		ap = &(*ap)->a_next;
	}

	/* Let the overlays have a chance at this */
	be_orig = op->o_bd;
	if ( SLAP_ISOVERLAY( be_orig ))
		op->o_bd = select_backend( be_orig->be_nsuffix, 0, 0 );

	if (( SLAP_OPATTRS( rs->sr_attr_flags ) || rs->sr_attrs ) &&
		op->o_bd && op->o_bd->be_operational != NULL )
	{
		rc = op->o_bd->be_operational( op, rs );
	}
	op->o_bd = be_orig;

	return rc;
}

#ifdef LDAP_SLAPI
static void init_group_pblock( Operation *op, Entry *target,
	Entry *e, struct berval *op_ndn, AttributeDescription *group_at )
{
	slapi_int_pblock_set_operation( op->o_pb, op );

	slapi_pblock_set( op->o_pb,
		SLAPI_X_GROUP_ENTRY, (void *)e );
	slapi_pblock_set( op->o_pb,
		SLAPI_X_GROUP_OPERATION_DN, (void *)op_ndn->bv_val );
	slapi_pblock_set( op->o_pb,
		SLAPI_X_GROUP_ATTRIBUTE, (void *)group_at->ad_cname.bv_val );
	slapi_pblock_set( op->o_pb,
		SLAPI_X_GROUP_TARGET_ENTRY, (void *)target );
}

static int call_group_preop_plugins( Operation *op )
{
	int rc;

	rc = slapi_int_call_plugins( op->o_bd,
		SLAPI_X_PLUGIN_PRE_GROUP_FN, op->o_pb );
	if ( rc < 0 ) {
		if (( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,
			(void *)&rc ) != 0 ) || rc == LDAP_SUCCESS )
		{
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		}
	} else {
		rc = LDAP_SUCCESS;
	}

	return rc;
}

static void call_group_postop_plugins( Operation *op )
{
	(void) slapi_int_call_plugins( op->o_bd, SLAPI_X_PLUGIN_POST_GROUP_FN, op->o_pb );
}
#endif /* LDAP_SLAPI */


/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* backend.c - routines for dealing with back-end databases */


#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include <sys/stat.h>

#include "slap.h"
#include "lutil.h"
#include "lber_pvt.h"

/*
 * If a module is configured as dynamic, its header should not
 * get included into slapd. While this is a general rule and does
 * not have much of an effect in UNIX, this rule should be adhered
 * to for Windows, where dynamic object code should not be implicitly
 * imported into slapd without appropriate __declspec(dllimport) directives.
 */

#if defined(SLAPD_BDB) && !defined(SLAPD_BDB_DYNAMIC)
#include "back-bdb/external.h"
#endif
#if defined(SLAPD_DNSSRV) && !defined(SLAPD_DNSSRV_DYNAMIC)
#include "back-dnssrv/external.h"
#endif
#if defined(SLAPD_LDAP) && !defined(SLAPD_LDAP_DYNAMIC)
#include "back-ldap/external.h"
#endif
#if defined(SLAPD_LDBM) && !defined(SLAPD_LDBM_DYNAMIC)
#include "back-ldbm/external.h"
#endif
#if defined(SLAPD_META) && !defined(SLAPD_META_DYNAMIC)
#include "back-meta/external.h"
#endif
#if defined(SLAPD_MONITOR) && !defined(SLAPD_MONITOR_DYNAMIC)
#include "back-monitor/external.h"
#endif
#if defined(SLAPD_NULL) && !defined(SLAPD_NULL_DYNAMIC)
#include "back-null/external.h"
#endif
#if defined(SLAPD_PASSWD) && !defined(SLAPD_PASSWD_DYNAMIC)
#include "back-passwd/external.h"
#endif
#if defined(SLAPD_PERL) && !defined(SLAPD_PERL_DYNAMIC)
#include "back-perl/external.h"
#endif
#if defined(SLAPD_SHELL) && !defined(SLAPD_SHELL_DYNAMIC)
#include "back-shell/external.h"
#endif
#if defined(SLAPD_TCL) && !defined(SLAPD_TCL_DYNAMIC)
#include "back-tcl/external.h"
#endif
#if defined(SLAPD_SQL) && !defined(SLAPD_SQL_DYNAMIC)
#include "back-sql/external.h"
#endif
#if defined(SLAPD_PRIVATE) && !defined(SLAPD_PRIVATE_DYNAMIC)
#include "private/external.h"
#endif

static BackendInfo binfo[] = {
#if defined(SLAPD_BDB) && !defined(SLAPD_BDB_DYNAMIC)
	{"bdb",	bdb_initialize},
#endif
#if defined(SLAPD_DNSSRV) && !defined(SLAPD_DNSSRV_DYNAMIC)
	{"dnssrv",	dnssrv_back_initialize},
#endif
#if defined(SLAPD_LDAP) && !defined(SLAPD_LDAP_DYNAMIC)
	{"ldap",	ldap_back_initialize},
#endif
#if defined(SLAPD_LDBM) && !defined(SLAPD_LDBM_DYNAMIC)
	{"ldbm",	ldbm_back_initialize},
#endif
#if defined(SLAPD_META) && !defined(SLAPD_META_DYNAMIC)
	{"meta",	meta_back_initialize},
#endif
#if defined(SLAPD_MONITOR) && !defined(SLAPD_MONITOR_DYNAMIC)
	{"monitor",	monitor_back_initialize},
#endif
#if defined(SLAPD_NULL) && !defined(SLAPD_NULL_DYNAMIC)
	{"null",	null_back_initialize},
#endif
#if defined(SLAPD_PASSWD) && !defined(SLAPD_PASSWD_DYNAMIC)
	{"passwd",	passwd_back_initialize},
#endif
#if defined(SLAPD_PERL) && !defined(SLAPD_PERL_DYNAMIC)
	{"perl",	perl_back_initialize},
#endif
#if defined(SLAPD_SHELL) && !defined(SLAPD_SHELL_DYNAMIC)
	{"shell",	shell_back_initialize},
#endif
#if defined(SLAPD_TCL) && !defined(SLAPD_TCL_DYNAMIC)
	{"tcl",		tcl_back_initialize},
#endif
#if defined(SLAPD_SQL) && !defined(SLAPD_SQL_DYNAMIC)
	{"sql",		sql_back_initialize},
#endif
	/* for any private backend */
#if defined(SLAPD_PRIVATE) && !defined(SLAPD_PRIVATE_DYNAMIC)
	{"private",	private_back_initialize},
#endif
	{NULL}
};

int			nBackendInfo = 0;
BackendInfo	*backendInfo = NULL;

int			nBackendDB = 0; 
BackendDB	*backendDB = NULL;

int backend_init(void)
{
	int rc = -1;

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

   if ((rc = aBackendInfo->bi_init(aBackendInfo)) != 0) {
#ifdef NEW_LOGGING
       	LDAP_LOG( BACKEND, ERR, 
                  "backend_add:  initialization for type \"%s\" failed\n",
                  aBackendInfo->bi_type, 0, 0 );
#else
      Debug( LDAP_DEBUG_ANY,
	     "backend_add: initialization for type \"%s\" failed\n",
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
	 AC_MEMCPY(newBackendInfo, backendInfo, sizeof(BackendInfo) * 
		nBackendInfo);
      } else {
	 newBackendInfo = ch_realloc(backendInfo, sizeof(BackendInfo) * 
				     (nBackendInfo + 1));
      }
      AC_MEMCPY(&newBackendInfo[nBackendInfo], aBackendInfo, 
	     sizeof(BackendInfo));
      backendInfo = newBackendInfo;
      nBackendInfo++;

      return 0;
   }	    
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
		/* startup a specific backend database */
#ifdef NEW_LOGGING
		LDAP_LOG( BACKEND, DETAIL1, "backend_startup:  starting \"%s\"\n",
			   be->be_suffix[0].bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"backend_startup: starting \"%s\"\n",
			be->be_suffix[0].bv_val, 0, 0 );
#endif

		if ( be->bd_info->bi_open ) {
			rc = be->bd_info->bi_open( be->bd_info );
			if ( rc != 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACKEND, CRIT, "backend_startup: bi_open failed!\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_open failed!\n",
					0, 0, 0 );
#endif

				return rc;
			}
		}

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
				return rc;
			}
		}

		return rc;
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

	/* open each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		/* append global access controls */
		acl_append( &backendDB[i].be_acl, global_acl );

		if ( backendDB[i].bd_info->bi_db_open ) {
			rc = backendDB[i].bd_info->bi_db_open(
				&backendDB[i] );
			if ( rc != 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACKEND, CRIT, 
					"backend_startup: bi_db_open(%d) failed! (%d)\n", i, rc, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"backend_startup: bi_db_open(%d) failed! (%d)\n",
					i, rc, 0 );
#endif
				return rc;
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
    const char	*type
)
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
			if (( backends[i].be_flags & SLAP_BFLAG_GLUE_SUBORDINATE )
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

					if( manageDSAit && len == dnlen ) {
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
    Backend	*be,
    struct berval	*bvsuffix
)
{
	int	i;

	for ( i = 0; be->be_nsuffix != NULL && be->be_nsuffix[i].bv_val != NULL; i++ ) {
		if ( ber_bvcmp( &be->be_nsuffix[i], bvsuffix ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}

int
be_isroot( Backend *be, struct berval *ndn )
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
be_isupdate( Backend *be, struct berval *ndn )
{
	if ( !ndn->bv_len ) {
		return( 0 );
	}

	if ( !be->be_update_ndn.bv_len ) {
		return( 0 );
	}

	return dn_match( &be->be_update_ndn, ndn );
}

struct berval *
be_root_dn( Backend *be )
{
	return &be->be_rootdn;
}

int
be_isroot_pw( Backend *be,
	Connection *conn,
	struct berval *ndn,
	struct berval *cred )
{
	int result;

	if ( ! be_isroot( be, ndn ) ) {
		return 0;
	}

	if( be->be_rootpw.bv_len == 0 ) {
		return 0;
	}

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = conn->c_sasl_context;
#endif
#endif

	result = lutil_passwd( &be->be_rootpw, cred, NULL );

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
	BackendDB *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	int rw )
{
	if ( be->be_release ) {
		/* free and release entry from backend */
		return be->be_release( be, conn, op, e, rw );
	} else {
		/* free entry */
		entry_free( e );
		return 0;
	}
}

int
backend_unbind(
	Connection   *conn,
	Operation    *op
)
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_unbind ) {
			(*backends[i].be_unbind)( &backends[i], conn, op );
		}
	}

	return 0;
}

int
backend_connection_init(
	Connection   *conn
)
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
	Connection   *conn
)
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
	Backend *be,
	Connection *conn,
	Operation *op,
	const char **text )
{
	LDAPControl **ctrls;
	ctrls = op->o_ctrls;
	if( ctrls == NULL ) {
		return LDAP_SUCCESS;
	}

	if ( be->be_controls == NULL ) {
		*text = "control unavailable in context";
		return LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
	}

	for( ; *ctrls != NULL ; ctrls++ ) {
		if( (*ctrls)->ldctl_iscritical &&
			!ldap_charray_inlist( be->be_controls, (*ctrls)->ldctl_oid ) )
		{
			*text = "control unavailable in context";
			return LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
		}
	}

	return LDAP_SUCCESS;
}

int
backend_check_restrictions(
	Backend *be,
	Connection *conn,
	Operation *op,
	struct berval *opdata,
	const char **text )
{
	int rc;
	slap_mask_t restrictops;
	slap_mask_t requires;
	slap_mask_t opflag;
	slap_ssf_set_t *ssf;
	int updateop = 0;
	int starttls = 0;
	int session = 0;

	if( be ) {
		rc = backend_check_controls( be, conn, op, text );

		if( rc != LDAP_SUCCESS ) {
			return rc;
		}

		restrictops = be->be_restrictops;
		requires = be->be_requires;
		ssf = &be->be_ssf_set;

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

		{
			struct berval bv = BER_BVC( LDAP_EXOP_START_TLS );
			if( ber_bvcmp( opdata, &bv ) == 0 ) {
				session++;
				starttls++;
				break;
			}
		}

		{
			struct berval bv = BER_BVC( LDAP_EXOP_X_WHO_AM_I );
			if( ber_bvcmp( opdata, &bv ) == 0 ) {
				break;
			}
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
		*text = "restrict operations internal error";
		return LDAP_OTHER;
	}

	if ( !starttls ) {
		/* these checks don't apply to StartTLS */

		if( op->o_transport_ssf < ssf->sss_transport ) {
			*text = "transport confidentiality required";
			return LDAP_CONFIDENTIALITY_REQUIRED;
		}

		if( op->o_tls_ssf < ssf->sss_tls ) {
			*text = "TLS confidentiality required";
			return LDAP_CONFIDENTIALITY_REQUIRED;
		}

		if( op->o_tag != LDAP_REQ_BIND || opdata == NULL ) {
			/* these checks don't apply to SASL bind */

			if( op->o_sasl_ssf < ssf->sss_sasl ) {
				*text = "SASL confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}

			if( op->o_ssf < ssf->sss_ssf ) {
				*text = "confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}
		}

		if( updateop ) {
			if( op->o_transport_ssf < ssf->sss_update_transport ) {
				*text = "transport update confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}

			if( op->o_tls_ssf < ssf->sss_update_tls ) {
				*text = "TLS update confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}

			if( op->o_sasl_ssf < ssf->sss_update_sasl ) {
				*text = "SASL update confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}

			if( op->o_ssf < ssf->sss_update_ssf ) {
				*text = "update confidentiality required";
				return LDAP_CONFIDENTIALITY_REQUIRED;
			}

			if( op->o_ndn.bv_len == 0 ) {
				*text = "modifications require authentication";
				return LDAP_STRONG_AUTH_REQUIRED;
			}
		}
	}

	if ( !session ) {
		/* these checks don't apply to Bind, StartTLS, or Unbind */

		if( requires & SLAP_REQUIRE_STRONG ) {
			/* should check mechanism */
			if( ( op->o_transport_ssf < ssf->sss_transport
				&& op->o_authmech.bv_len == 0 ) || op->o_dn.bv_len == 0 )
			{
				*text = "strong authentication required";
				return LDAP_STRONG_AUTH_REQUIRED;
			}
		}

		if( requires & SLAP_REQUIRE_SASL ) {
			if( op->o_authmech.bv_len == 0 || op->o_dn.bv_len == 0 ) {
				*text = "SASL authentication required";
				return LDAP_STRONG_AUTH_REQUIRED;
			}
		}
			
		if( requires & SLAP_REQUIRE_AUTHC ) {
			if( op->o_dn.bv_len == 0 ) {
				*text = "authentication required";
				return LDAP_UNWILLING_TO_PERFORM;
			}
		}

		if( requires & SLAP_REQUIRE_BIND ) {
			int version;
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
			version = conn->c_protocol;
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

			if( !version ) {
				/* no bind has occurred */
				*text = "BIND required";
				return LDAP_OPERATIONS_ERROR;
			}
		}

		if( requires & SLAP_REQUIRE_LDAP_V3 ) {
			if( op->o_protocol < LDAP_VERSION3 ) {
				/* no bind has occurred */
				*text = "operation restricted to LDAPv3 clients";
				return LDAP_OPERATIONS_ERROR;
			}
		}
	}

	if( restrictops & opflag ) {
		if( restrictops == SLAP_RESTRICT_OP_READS ) {
			*text = "read operations restricted";
		} else {
			*text = "operation restricted";
		}
		return LDAP_UNWILLING_TO_PERFORM;
 	}

	return LDAP_SUCCESS;
}

int backend_check_referrals(
	Backend *be,
	Connection *conn,
	Operation *op,
	struct berval *dn,
	struct berval *ndn )
{
	int rc = LDAP_SUCCESS;

	if( be->be_chk_referrals ) {
		const char *text;

		rc = be->be_chk_referrals( be,
			conn, op, dn, ndn, &text );

		if( rc != LDAP_SUCCESS && rc != LDAP_REFERRAL ) {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
		}
	}

	return rc;
}

int 
backend_group(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	struct berval *gr_ndn,
	struct berval *op_ndn,
	ObjectClass *group_oc,
	AttributeDescription *group_at
)
{
	GroupAssertion *g;

	if ( op->o_abandon ) return SLAPD_ABANDON;

	if ( !dn_match( &target->e_nname, gr_ndn ) ) {
		/* we won't attempt to send it to a different backend */
		
		be = select_backend( gr_ndn, 0, 0 );

		if (be == NULL) {
			return LDAP_NO_SUCH_OBJECT;
		}
	} 

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	for (g = conn->c_groups; g; g=g->ga_next) {
		if (g->ga_be != be || g->ga_oc != group_oc ||
			g->ga_at != group_at || g->ga_len != gr_ndn->bv_len)
			continue;
		if (strcmp( g->ga_ndn, gr_ndn->bv_val ) == 0)
			break;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	if (g) {
		return g->ga_res;
	}

	if( be->be_group ) {
		int res = be->be_group( be, conn, op,
			target, gr_ndn, op_ndn,
			group_oc, group_at );
		
		if ( op->o_tag != LDAP_REQ_BIND && !op->o_do_not_cache ) {
			g = ch_malloc(sizeof(GroupAssertion) + gr_ndn->bv_len);
			g->ga_be = be;
			g->ga_oc = group_oc;
			g->ga_at = group_at;
			g->ga_res = res;
			g->ga_len = gr_ndn->bv_len;
			strcpy(g->ga_ndn, gr_ndn->bv_val);
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
			g->ga_next = conn->c_groups;
			conn->c_groups = g;
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
		}

		return res;
	}

	return LDAP_UNWILLING_TO_PERFORM;
}

int 
backend_attribute(
	Backend	*be,
	Connection *conn,
	Operation *op,
	Entry	*target,
	struct berval	*edn,
	AttributeDescription *entry_at,
	BerVarray *vals
)
{
	if ( target == NULL || !dn_match( &target->e_nname, edn ) ) {
		/* we won't attempt to send it to a different backend */
		
		be = select_backend( edn, 0, 0 );

		if (be == NULL) {
			return LDAP_NO_SUCH_OBJECT;
		}
	} 

	if( be->be_attribute ) {
		return be->be_attribute( be, conn, op, target, edn,
			entry_at, vals );
	}

	return LDAP_UNWILLING_TO_PERFORM;
}

Attribute *backend_operational(
	Backend *be,
	Connection *conn,
	Operation *op,
	Entry *e,
	AttributeName *attrs,
	int opattrs	)
{
	Attribute *a = NULL, **ap = &a;

	/*
	 * If operational attributes (allegedly) are required, 
	 * and the backend supports specific operational attributes, 
	 * add them to the attribute list
	 */
#ifdef SLAPD_SCHEMA_DN
	if ( opattrs || ( attrs &&
		ad_inlist( slap_schema.si_ad_subschemaSubentry, attrs )) ) {
		*ap = slap_operational_subschemaSubentry( be );
		ap = &(*ap)->a_next;
	}
#endif
	if ( ( opattrs || attrs ) && be && be->be_operational != NULL ) {
		( void )be->be_operational( be, conn, op, e, attrs, opattrs, ap );
	}

	return a;
}


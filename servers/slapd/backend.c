/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

#ifdef SLAPD_LDAP
#include "back-ldap/external.h"
#endif
#ifdef SLAPD_LDBM
#include "back-ldbm/external.h"
#endif
#ifdef SLAPD_BDB2
#include "back-bdb2/external.h"
#endif
#ifdef SLAPD_PASSWD
#include "back-passwd/external.h"
#endif
#ifdef SLAPD_PERL
#include "back-perl/external.h"
#endif
#ifdef SLAPD_SHELL
#include "back-shell/external.h"
#endif
#ifdef SLAPD_TCL
#include "back-tcl/external.h"
#endif

static BackendInfo binfo[] = {
#if defined(SLAPD_LDAP) && !defined(SLAPD_LDAP_DYNAMIC)
	{"ldap",	ldap_back_initialize},
#endif
#if defined(SLAPD_LDBM) && !defined(SLAPD_LDBM_DYNAMIC)
	{"ldbm",	ldbm_back_initialize},
#endif
#if defined(SLAPD_BDB2) && !defined(SLAPD_BDB2_DYNAMIC)
	{"bdb2",	bdb2_back_initialize},
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
		Debug( LDAP_DEBUG_ANY,
			"backend_init: already initialized.\n", 0, 0, 0 );
		return -1;
	}

	for( ;
		binfo[nBackendInfo].bi_type != NULL;
		nBackendInfo++ )
	{
		rc = binfo[nBackendInfo].bi_init( &binfo[nBackendInfo] );

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_init: initialized for type \"%s\"\n",
					binfo[nBackendInfo].bi_type, 0, 0 );

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
	Debug( LDAP_DEBUG_ANY,
		"backend_init: failed\n",
		0, 0, 0 );

	return rc;
#endif /* SLAPD_MODULES */
}

int backend_add(BackendInfo *aBackendInfo)
{
   int rc = 0;

   if ((rc = aBackendInfo->bi_init(aBackendInfo)) != 0) {
      Debug( LDAP_DEBUG_ANY,
	     "backend_add: initialization for type \"%s\" failed\n",
	     aBackendInfo->bi_type, 0, 0 );
      return rc;
   }

   /* now add the backend type to the Backend Info List */
   {
      BackendInfo *newBackendInfo = 0;

      /* if backendInfo == binfo no deallocation of old backendInfo */
      if (backendInfo == binfo) {
	 newBackendInfo = ch_calloc(nBackendInfo + 1, sizeof(BackendInfo));
	 memcpy(newBackendInfo, backendInfo, sizeof(BackendInfo) * 
		nBackendInfo);
      } else {
	 newBackendInfo = ch_realloc(backendInfo, sizeof(BackendInfo) * 
				     (nBackendInfo + 1));
      }
      memcpy(&newBackendInfo[nBackendInfo], aBackendInfo, 
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
		Debug( LDAP_DEBUG_ANY,
			"backend_startup: %d databases to startup.\n",
			nBackendDB, 0, 0 );
		return 1;
	}

	if(be != NULL) {
		/* startup a specific backend database */
		Debug( LDAP_DEBUG_TRACE,
			"backend_startup: starting database\n",
			0, 0, 0 );

		if ( be->bd_info->bi_open ) {
			rc = be->bd_info->bi_open( be->bd_info );
		}

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_open failed!\n",
				0, 0, 0 );
			return rc;
		}

		if ( be->bd_info->bi_db_open ) {
			rc = be->bd_info->bi_db_open( be );
		}

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_db_open failed!\n",
				0, 0, 0 );
			return rc;
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
		}

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_open %d failed!\n",
				i, 0, 0 );
			return rc;
		}
	}

	/* open each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		/* append global access controls */
		acl_append( &backendDB[i].be_acl, global_acl );

		if ( backendDB[i].bd_info->bi_db_open ) {
			rc = backendDB[i].bd_info->bi_db_open(
				&backendDB[i] );
		}

		if(rc != 0) {
			Debug( LDAP_DEBUG_ANY,
				"backend_startup: bi_db_open %d failed!\n",
				i, 0, 0 );
			return rc;
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
				"backend_close: bi_close %s failed!\n",
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

	return 0;
}

int backend_destroy(void)
{
	int i;

	/* destroy each backend database */
	for( i = 0; i < nBackendDB; i++ ) {
		if ( backendDB[i].bd_info->bi_db_destroy ) {
			backendDB[i].bd_info->bi_db_destroy(
				&backendDB[i] );
		}
	}

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
	be->be_sizelimit = defsize;
	be->be_timelimit = deftime;
	be->be_dfltaccess = global_default_access;

 	/* assign a default depth limit for alias deref */
	be->be_max_deref_depth = SLAPD_DEFAULT_MAXDEREFDEPTH; 

	be->be_realm = global_realm != NULL
		? ch_strdup( global_realm ) : NULL;

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
select_backend( const char * dn )
{
	int	i, j, len, dnlen;

	dnlen = strlen( dn );
	for ( i = 0; i < nbackends; i++ ) {
		for ( j = 0; backends[i].be_nsuffix != NULL &&
		    backends[i].be_nsuffix[j] != NULL; j++ )
		{
			len = strlen( backends[i].be_nsuffix[j] );

			if ( len > dnlen ) {
				continue;
			}

			if ( strcmp( backends[i].be_nsuffix[j],
			    dn + (dnlen - len) ) == 0 ) {
				return( &backends[i] );
			}
		}
	}

#ifdef LDAP_ALLOW_NULL_SEARCH_BASE
	/* Add greg@greg.rim.or.jp
	 * It's quick hack for cheap client
	 * Some browser offer a NULL base at ldap_search
	 *
	 * Should only be used as a last resort. -Kdz
	 */
	if(dnlen == 0) {
		Debug( LDAP_DEBUG_TRACE,
			"select_backend: use default backend\n", 0, 0, 0 );
		return( &backends[0] );
	}
#endif /* LDAP_ALLOW_NULL_SEARCH_BASE */

	return( NULL );
}

int
be_issuffix(
    Backend	*be,
    const char	*suffix
)
{
	int	i;

	for ( i = 0; be->be_nsuffix != NULL && be->be_nsuffix[i] != NULL; i++ ) {
		if ( strcmp( be->be_nsuffix[i], suffix ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}

int
be_isroot( Backend *be, const char *ndn )
{
	int rc;

	if ( ndn == NULL || be->be_root_ndn == NULL ) {
		return( 0 );
	}

	rc = strcmp( be->be_root_ndn, ndn ) ? 0 : 1;

	return(rc);
}

char *
be_root_dn( Backend *be )
{
	if ( be->be_root_dn == NULL ) {
		return( "" );
	}

	return be->be_root_dn;
}

int
be_isroot_pw( Backend *be, const char *ndn, struct berval *cred )
{
	int result;

	if ( ! be_isroot( be, ndn ) ) {
		return( 0 );
	}

#ifdef SLAPD_CRYPT
	ldap_pvt_thread_mutex_lock( &crypt_mutex );
#endif

	result = lutil_passwd( cred->bv_val, be->be_root_pw, NULL );

#ifdef SLAPD_CRYPT
	ldap_pvt_thread_mutex_unlock( &crypt_mutex );
#endif

	return result == 0;
}

int
be_entry_release_rw( Backend *be, Entry *e, int rw )
{
	if ( be->be_release ) {
		/* free and release entry from backend */
		return be->be_release( be, e, rw );
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

int 
backend_group(
	Backend	*be,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
	const char	*objectclassValue,
	const char	*groupattrName
)
{
	if (be->be_group)
		return( be->be_group(be, target, gr_ndn, op_ndn,
			objectclassValue, groupattrName) );
	else
		return(1);
}

#ifdef SLAPD_SCHEMA_DN
Attribute *backend_subschemasubentry( Backend *be )
{
	/* should be backend specific */
	static struct berval ss_val = {
		sizeof(SLAPD_SCHEMA_DN)-1,
		SLAPD_SCHEMA_DN };
	static struct berval *ss_vals[2] = { &ss_val, NULL };
	static Attribute ss_attr = {
		"subschemasubentry",
		ss_vals,
		SYNTAX_DN | SYNTAX_CIS,
		NULL
	};

	return &ss_attr;
}
#endif

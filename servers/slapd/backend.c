/* backend.c - routines for dealing with back-end databases */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include "slap.h"

#ifdef LDAP_LDBM
extern int	ldbm_back_bind();
extern int	ldbm_back_unbind();
extern int	ldbm_back_search();
extern int	ldbm_back_compare();
extern int	ldbm_back_modify();
extern int	ldbm_back_modrdn();
extern int	ldbm_back_add();
extern int	ldbm_back_delete();
extern int	ldbm_back_abandon();
extern int	ldbm_back_config();
extern int	ldbm_back_init();
extern int	ldbm_back_close();
extern int      ldbm_back_group();
#endif

#ifdef LDAP_PASSWD
extern int	passwd_back_search();
extern int	passwd_back_config();
#endif

#ifdef LDAP_SHELL
extern int	shell_back_bind();
extern int	shell_back_unbind();
extern int	shell_back_search();
extern int	shell_back_compare();
extern int	shell_back_modify();
extern int	shell_back_modrdn();
extern int	shell_back_add();
extern int	shell_back_delete();
extern int	shell_back_abandon();
extern int	shell_back_config();
extern int	shell_back_init();
#endif

extern int	defsize;
extern int	deftime;

#define BACKEND_GRAB_SIZE	10

int		nbackends;
Backend		*backends;
static int	maxbackends;

Backend *
new_backend(
    char	*type
)
{
	Backend	*be;
	int	foundit;

	if ( nbackends == maxbackends ) {
		maxbackends += BACKEND_GRAB_SIZE;
		backends = (Backend *) ch_realloc( (char *) backends,
		    maxbackends * sizeof(Backend) );
		memset( &backends[nbackends], '\0', BACKEND_GRAB_SIZE *
		    sizeof(Backend) );
	}

	be = &backends[nbackends++];
	be->be_sizelimit = defsize;
	be->be_timelimit = deftime;
	foundit = 0;

#ifdef LDAP_LDBM
	if ( strcasecmp( type, "ldbm" ) == 0 ) {
		be->be_bind = ldbm_back_bind;
		be->be_unbind = ldbm_back_unbind;
		be->be_search = ldbm_back_search;
		be->be_compare = ldbm_back_compare;
		be->be_modify = ldbm_back_modify;
		be->be_modrdn = ldbm_back_modrdn;
		be->be_add = ldbm_back_add;
		be->be_delete = ldbm_back_delete;
		be->be_abandon = ldbm_back_abandon;
		be->be_config = ldbm_back_config;
		be->be_init = ldbm_back_init;
		be->be_close = ldbm_back_close;
#ifdef ACLGROUP
		be->be_group = ldbm_back_group;
#endif
		be->be_type = "ldbm";
		foundit = 1;
	}
#endif

#ifdef LDAP_PASSWD
	if ( strcasecmp( type, "passwd" ) == 0 ) {
		be->be_bind = NULL;
		be->be_unbind = NULL;
		be->be_search = passwd_back_search;
		be->be_compare = NULL;
		be->be_modify = NULL;
		be->be_modrdn = NULL;
		be->be_add = NULL;
		be->be_delete = NULL;
		be->be_abandon = NULL;
		be->be_config = passwd_back_config;
		be->be_init = NULL;
		be->be_close = NULL;
#ifdef ACLGROUP
		be->be_group = NULL;
#endif
		be->be_type = "passwd";
		foundit = 1;
	}
#endif

#ifdef LDAP_SHELL
	if ( strcasecmp( type, "shell" ) == 0 ) {
		be->be_bind = shell_back_bind;
		be->be_unbind = shell_back_unbind;
		be->be_search = shell_back_search;
		be->be_compare = shell_back_compare;
		be->be_modify = shell_back_modify;
		be->be_modrdn = shell_back_modrdn;
		be->be_add = shell_back_add;
		be->be_delete = shell_back_delete;
		be->be_abandon = shell_back_abandon;
		be->be_config = shell_back_config;
		be->be_init = shell_back_init;
		be->be_close = NULL;
#ifdef ACLGROUP
		be->be_group = NULL;
#endif
		be->be_type = "shell";
		foundit = 1;
	}
#endif

	if ( be->be_init != NULL ) {
		(*be->be_init)( be );
	}

	if ( foundit == 0 ) {
		fprintf( stderr, "Unrecognized database type (%s)\n", type );
		exit( 1 );
	}

	return( be );
}

Backend *
select_backend( char * dn )
{
	int	i, j, len, dnlen;

	dnlen = strlen( dn );
	for ( i = 0; i < nbackends; i++ ) {
		for ( j = 0; backends[i].be_suffix != NULL &&
		    backends[i].be_suffix[j] != NULL; j++ ) {
			len = strlen( backends[i].be_suffix[j] );

			if ( len > dnlen ) {
				continue;
			}

			if ( strcasecmp( backends[i].be_suffix[j],
			    dn + (dnlen - len) ) == 0 ) {
				return( &backends[i] );
			}
		}
	}

	return( NULL );
}

int
be_issuffix(
    Backend	*be,
    char	*suffix
)
{
	int	i;

	for ( i = 0; be->be_suffix != NULL && be->be_suffix[i] != NULL; i++ ) {
		if ( strcasecmp( be->be_suffix[i], suffix ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}

int
be_isroot( Backend *be, char *dn )
{
	if ( dn == NULL ) {
		return( 0 );
	}

	return( be->be_rootdn ? strcasecmp( be->be_rootdn, dn ) == 0
	    : 0 );
}

int
be_isroot_pw( Backend *be, char *dn, struct berval *cred )
{
	if ( ! be_isroot( be, dn ) || be->be_rootpw == NULL ) {
		return( 0 );
	}

	return( strcmp( be->be_rootpw, cred->bv_val ) == 0 );
}

void
be_close()
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_close != NULL ) {
			(*backends[i].be_close)( &backends[i] );
		}
	}
}


void
be_unbind(
	Connection   *conn,
	Operation    *op
)
{
	int	i;

	for ( i = 0; i < nbackends; i++ ) {
		if ( backends[i].be_unbind != NULL ) {
			(*backends[i].be_unbind)( &backends[i], conn, op );
		}
	}
}

#ifdef ACLGROUP
int 
be_group(Backend *be, char *bdn, char *edn)
{
        if (be->be_group)
                return(be->be_group(be, bdn, edn));
        else
                return(1);
}
#endif

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

struct ldapoptions openldap_ldap_global_options; 

#undef gopts
#define gopts openldap_ldap_global_options

int	openldap_ldap_initialized = 0;

void openldap_ldap_initialize( void )
{
	if ( openldap_ldap_initialized ) {
		return;
	}

	gopts.ldo_version =	LDAP_VERSION2;
	gopts.ldo_deref =	LDAP_DEREF_NEVER;
	gopts.ldo_timelimit = LDAP_NO_LIMIT;
	gopts.ldo_sizelimit = LDAP_NO_LIMIT;

	gopts.ldo_defhost = strdup("localhost");
	gopts.ldo_defport = LDAP_PORT;

	LDAP_BOOL_ZERO(&gopts);

#if defined( LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS ) || \
	LDAP_VERSION_MAX > LDAP_VERSION2
	LDAP_BOOL_SET(&gopts, LDAP_BOOL_REFERRALS);
#endif

	openldap_ldap_initialized = 1;
}

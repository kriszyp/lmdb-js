#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

struct ldap openldap_ld_globals;

int	openldap_ldap_initialized = 0;

void openldap_ldap_initialize( void )
{
	if ( openldap_ldap_initialized ) {
		return;
	}

	openldap_ldap_initialized = 1;
}

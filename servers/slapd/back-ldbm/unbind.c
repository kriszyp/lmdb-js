/* unbind.c - handle an ldap unbind operation */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"

int
ldbm_back_unbind(
	Backend     *be,
	Connection  *conn,
	Operation   *op
)
{
	return( 0 );
}

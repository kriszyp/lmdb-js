/* compare.c - ldbm backend compare routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

extern Attribute	*attr_find();

int
ldbm_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Ava		*ava
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched;
	Entry		*e;
	Attribute	*a;
	int		i, rc;

	/* get entry with reader lock */
	if ( (e = dn2entry_r( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		return( 1 );
	}

	/* check for deleted */
	if ( ! access_allowed( be, conn, op, e, ava->ava_type, &ava->ava_value,
	    op->o_dn, ACL_COMPARE ) ) {
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, "", "" );
		rc = 1;
		goto return_results;
	}

	if ( (a = attr_find( e->e_attrs, ava->ava_type )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_ATTRIBUTE, "", "" );
		rc = 1;
		goto return_results;
	}

	if ( value_find( a->a_vals, &ava->ava_value, a->a_syntax, 1 ) == 0 ) 
		send_ldap_result( conn, op, LDAP_COMPARE_TRUE, "", "" );
	else
		send_ldap_result( conn, op, LDAP_COMPARE_FALSE, "", "" );

	rc = 0;

return_results:;
	cache_return_entry_r( &li->li_cache, e );
	return( rc );
}

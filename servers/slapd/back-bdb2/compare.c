/* compare.c - bdb2 backend compare routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int
bdb2i_back_compare_internal(
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
	int		rc;

	/* get entry with reader lock */
	if ( (e = bdb2i_dn2entry_r( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );

		if(matched == NULL) free(matched);
		return( 1 );
	}

	/* check for deleted */
	if ( ! access_allowed( be, conn, op, e,
		ava->ava_type, &ava->ava_value, ACL_COMPARE ) )
	{
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
	bdb2i_cache_return_entry_r( &li->li_cache, e );
	return( rc );
}


int
bdb2_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Ava		*ava
)
{
	DB_LOCK  lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	if ( bdb2i_enter_backend_r( &li->li_db_env, &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		return( 1 );

	}

	ret = bdb2i_back_compare_internal( be, conn, op, dn, ava );

	(void) bdb2i_leave_backend( &li->li_db_env, lock );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "conn=%d op=%d CMP elapsed=%s\n",
				conn->c_connid, op->o_opid, elapsed_time );
		free( elapsed_time );

	}

	return( ret );
}



/* compare.c - bdb2 backend compare routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int
bdb2i_back_compare_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Ava		*ava
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	Attribute	*a;
	int		rc;
	int		manageDSAit = get_manageDSAit( op );

	/* get entry with reader lock */
	if ( (e = bdb2i_dn2entry_r( be, dn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb2i_cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( 1 );
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		rc = 1;
		goto return_results;
	}

	if ( ! access_allowed( be, conn, op, e,
		ava->ava_type, &ava->ava_value, ACL_COMPARE ) )
	{
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		rc = 1;
		goto return_results;
	}

	if ( (a = attr_find( e->e_attrs, ava->ava_type )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_ATTRIBUTE,
			NULL, NULL, NULL, NULL );
		rc = 1;
		goto return_results;
	}

	if ( value_find( a->a_vals, &ava->ava_value, a->a_syntax, 1 ) == 0 ) 
		send_ldap_result( conn, op, LDAP_COMPARE_TRUE,
			NULL, NULL, NULL, NULL );
	else
		send_ldap_result( conn, op, LDAP_COMPARE_FALSE,
			NULL, NULL, NULL, NULL );

	rc = 0;

return_results:;
	bdb2i_cache_return_entry_r( &li->li_cache, e );
	return( rc );
}


int
bdb2_back_compare(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Ava		*ava
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_r( &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		return( 1 );

	}

	ret = bdb2i_back_compare_internal( be, conn, op, dn, ava );
	(void) bdb2i_leave_backend_r( lock );
	bdb2i_stop_timing( be->bd_info, time1, "CMP", conn, op );

	return( ret );
}



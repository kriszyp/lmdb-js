/* delete.c - bdb2 backend delete routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int
bdb2i_back_delete_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry	*matched = NULL;
	char	*pdn = NULL;
	Entry	*e, *p = NULL;
	int	rc = -1, manageDSAit;

	Debug(LDAP_DEBUG_ARGS, "==> bdb2i_back_delete: %s\n", dn, 0, 0);

	/* get entry with writer lock */
	if ( (e = bdb2i_dn2entry_w( be, dn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		Debug(LDAP_DEBUG_ARGS, "<=- bdb2i_back_delete: no such object %s\n",
			dn, 0, 0);

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

		return( -1 );
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
		goto return_results;
	}


	if ( bdb2i_has_children( be, e ) ) {
		Debug(LDAP_DEBUG_ARGS, "<=- bdb2i_back_delete: non leaf %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_WRITE ) )
	{
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: insufficient access %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}
#endif

	/* find parent's entry */
	if( (pdn = dn_parent( be, e->e_ndn )) != NULL ) {
		if( (p = bdb2i_dn2entry_w( be, pdn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: parent does not exist\n", 0, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: no access to parent\n", 0, 0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: no parent & not root\n", 0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}
	}

	/* delete from dn2id mapping */
	if ( bdb2i_dn2id_delete( be, e->e_ndn, e->e_id ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( bdb2i_id2entry_delete( be, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;

return_results:;
	if ( pdn != NULL ) free(pdn);

	if( p != NULL ) {
		/* free parent and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, p );

	}

	/* free entry and writer lock */
	bdb2i_cache_return_entry_w( &li->li_cache, e );

	if ( matched != NULL ) free(matched);

	return rc;
}


int
bdb2_back_delete(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_w( &lock ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		return( -1 );
	}

	ret = bdb2i_back_delete_internal( be, conn, op, ndn );
	(void) bdb2i_leave_backend_w( lock );
	bdb2i_stop_timing( be->bd_info, time1, "DEL", conn, op );

	return( ret );
}



/* delete.c - ldbm backend delete routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

extern Attribute	*attr_find();

int
ldbm_back_delete(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched = NULL;
        char            *pdn = NULL;
	Entry		*e, *p;

	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_delete: %s\n", dn, 0, 0);

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: no such object %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	Debug (LDAP_DEBUG_TRACE,
		"rdwr_Xchk: readers_reading: %d writer_writing: %d\n",
		e->e_rdwr.readers_reading, e->e_rdwr.writer_writing, 0);

	/* check for deleted */

	if ( has_children( be, e ) ) {
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: non leaf %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF, "",
		    "" );
		goto error_return;
	}

	if ( ! access_allowed( be, conn, op, e, "entry", NULL, op->o_dn,
	    ACL_WRITE ) ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: insufficient access %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, "", "" );
		goto error_return;
	}

	Debug (LDAP_DEBUG_TRACE,
		"rdwr_Xchk: readers_reading: %d writer_writing: %d\n",
		e->e_rdwr.readers_reading, e->e_rdwr.writer_writing, 0);

	/* XXX delete from parent's id2children entry XXX */
	pdn = dn_parent( be, dn );
	matched = NULL;
	p = dn2entry_r( be, pdn, &matched );
	if ( id2children_remove( be, p, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "","" );
                goto error_return;
	}

	/* delete from dn2id mapping */
	if ( dn2id_delete( be, e->e_dn ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto error_return;
	}

	/* delete from disk and cache */
	if ( id2entry_delete( be, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto error_return;
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );

	return( 0 );

error_return:;
	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	if( p )
		cache_return_entry_r( &li->li_cache, p );

	return( -1 );
}

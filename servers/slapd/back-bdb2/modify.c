/* modify.c - bdb2 backend modify routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int	add_values(Entry *e, LDAPMod *mod, char *dn);
static int	delete_values(Entry *e, LDAPMod *mod, char *dn);
static int	replace_values(Entry *e, LDAPMod *mod, char *dn);

static int
bdb2i_back_modify_internal(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched;
	LDAPModList	*ml;
	Entry		*e;
	int		i, err;

	Debug(LDAP_DEBUG_ARGS, "bdb2i_back_modify:\n", 0, 0, 0);

	if ( (e = bdb2i_dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched,
		    NULL );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	if ( (err = acl_check_modlist( be, conn, op, e, modlist )) != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, err, NULL, NULL );
		goto error_return;
	}

	for ( ml = modlist; ml != NULL; ml = ml->ml_next ) {
		LDAPMod	*mod = &ml->ml_mod;

		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			err = add_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_DELETE:
			err = delete_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_REPLACE:
			err = replace_values( e, mod, op->o_ndn );
			break;
		}

		if ( err != LDAP_SUCCESS ) {
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err, NULL, NULL );
			goto error_return;
		}
	}

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, NULL, NULL );
		goto error_return;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto error_return;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* modify indexes */
	if ( bdb2i_index_add_mods( be, modlist, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto error_return;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto error_return;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* change the entry itself */
	if ( bdb2i_id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	bdb2i_cache_return_entry_w( &li->li_cache, e );
	return( 0 );

error_return:;
	bdb2i_cache_return_entry_w( &li->li_cache, e );
	return( -1 );
}


int
bdb2_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist
)
{
	DB_LOCK  lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	if ( bdb2i_enter_backend_w( &li->li_db_env, &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		return( -1 );

	}

	/*  check, if a new default attribute index will be created,
		in which case we have to open the index file BEFORE TP  */
	if ( bdb2i_with_dbenv )
		bdb2i_check_default_attr_index_mod( li, modlist );

	 ret = bdb2i_back_modify_internal( be, conn, op, dn, modlist );

	(void) bdb2i_leave_backend( &li->li_db_env, lock );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "conn=%d op=%d MOD elapsed=%s\n",
				conn->c_connid, op->o_opid, elapsed_time );
		free( elapsed_time );

	}

	return( ret );
}


static int
add_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	int		i;
	Attribute	*a;

	/* check if the values we're adding already exist */
	if ( (a = attr_find( e->e_attrs, mod->mod_type )) != NULL ) {
		for ( i = 0; mod->mod_bvalues[i] != NULL; i++ ) {
			if ( value_find( a->a_vals, mod->mod_bvalues[i],
			    a->a_syntax, 3 ) == 0 ) {
				return( LDAP_TYPE_OR_VALUE_EXISTS );
			}
		}
	}

	/* no - add them */
	if( attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 ) {
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}

static int
delete_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	int		i, j, k, found;
	Attribute	*a;

	/* delete the entire attribute */
	if ( mod->mod_bvalues == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "removing entire attribute %s\n",
		    mod->mod_type, 0, 0 );
		return( attr_delete( &e->e_attrs, mod->mod_type ) ?
		    LDAP_NO_SUCH_ATTRIBUTE : LDAP_SUCCESS );
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->mod_type )) == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "could not find attribute %s\n",
		    mod->mod_type, 0, 0 );
		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	/* find each value to delete */
	for ( i = 0; mod->mod_bvalues[i] != NULL; i++ ) {
		found = 0;
		for ( j = 0; a->a_vals[j] != NULL; j++ ) {
			if ( value_cmp( mod->mod_bvalues[i], a->a_vals[j],
			    a->a_syntax, 3 ) != 0 ) {
				continue;
			}
			found = 1;

			/* found a matching value - delete it */
			ber_bvfree( a->a_vals[j] );
			for ( k = j + 1; a->a_vals[k] != NULL; k++ ) {
				a->a_vals[k - 1] = a->a_vals[k];
			}
			a->a_vals[k - 1] = NULL;
			break;
		}

		/* looked through them all w/o finding it */
		if ( ! found ) {
			Debug( LDAP_DEBUG_ARGS,
			    "could not find value for attr %s\n",
			    mod->mod_type, 0, 0 );
			return( LDAP_NO_SUCH_ATTRIBUTE );
		}
	}

	return( LDAP_SUCCESS );
}

static int
replace_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	(void) attr_delete( &e->e_attrs, mod->mod_type );

	if ( attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 ) {
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}

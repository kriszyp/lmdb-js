/* modify.c - ldbm backend modify routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

static void	add_lastmods(Operation *op, LDAPModList **ml);


static void
add_lastmods( Operation *op, LDAPModList **modlist )
{
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	LDAPModList		**m;
	LDAPModList		*tmp;
	struct tm	*ltm;
	time_t		currenttime;

	Debug( LDAP_DEBUG_TRACE, "add_lastmods\n", 0, 0, 0 );

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to modify these attrs */
	for ( m = modlist; *m != NULL; m = &(*m)->ml_next ) {
            if ( oc_check_no_usermod_attr( (*m)->ml_type ) ) {
                Debug( LDAP_DEBUG_TRACE,
					"add_lastmods: found no user mod attr: %s\n",
					(*m)->ml_type, 0, 0 );
                tmp = *m;
                *m = (*m)->ml_next;
                free( tmp->ml_type );
                if ( tmp->ml_bvalues != NULL ) {
                    ber_bvecfree( tmp->ml_bvalues );
                }
                free( tmp );
                if (!*m)
                    break;
            }
        }

	if ( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		bv.bv_val = "NULLDN";
		bv.bv_len = strlen( bv.bv_val );
	} else {
		bv.bv_val = op->o_dn;
		bv.bv_len = strlen( bv.bv_val );
	}
	tmp = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );
	tmp->ml_type = ch_strdup( "modifiersname" );
	tmp->ml_op = LDAP_MOD_REPLACE;
	tmp->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	tmp->ml_bvalues[0] = ber_bvdup( &bv );
	tmp->ml_next = *modlist;
	*modlist = tmp;

	currenttime = slap_get_time();
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );
	tmp = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );
	tmp->ml_type = ch_strdup( "modifytimestamp" );
	tmp->ml_op = LDAP_MOD_REPLACE;
	tmp->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	tmp->ml_bvalues[0] = ber_bvdup( &bv );
	tmp->ml_next = *modlist;
	*modlist = tmp;

}

/* We need this function because of LDAP modrdn. If we do not 
 * add this there would be a bunch of code replication here 
 * and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 */ 

int ldbm_modify_internal(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist,
    Entry	*e 
)
{
	int err;
	LDAPMod		*mod;
	LDAPModList	*ml;
	Attribute	*a;

	if ( ((be->be_lastmod == ON)
	      || ((be->be_lastmod == UNDEFINED)&&(global_lastmod == ON)))
	     && (be->be_update_ndn == NULL)) {

	        /* XXX: It may be wrong, it changes mod time even if 
		 * mod fails!
		 */
		add_lastmods( op, &modlist );

	}


	if ( (err = acl_check_modlist( be, conn, op, e, modlist ))
	     != LDAP_SUCCESS )
	{
		send_ldap_result( conn, op, err,
			NULL, NULL, NULL, NULL );
		return -1;
	}

	for ( ml = modlist; ml != NULL; ml = ml->ml_next ) {

		mod = &ml->ml_mod;

		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			err = add_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_DELETE:
			err = delete_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_REPLACE:
			/* Need to remove all values from indexes before they
			 * are lost.
			 */
		        if( e->e_attrs
			    && ((a = attr_find( e->e_attrs, mod->mod_type ))
			   != NULL) ) {

			    (void) index_change_values( be,
							mod->mod_type,
							a->a_vals,
							e->e_id,
							__INDEX_DELETE_OP);
			}

			err = replace_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_SOFTADD:
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->mod_op = LDAP_MOD_ADD;
 			if ( (err = add_values( e, mod, op->o_ndn ))
 				==  LDAP_TYPE_OR_VALUE_EXISTS ) {
 
 				err = LDAP_SUCCESS;
 				mod->mod_op = LDAP_MOD_SOFTADD;
 
 			}
 			break;
		}

		if ( err != LDAP_SUCCESS ) {
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err,
				NULL, NULL, NULL, NULL );
			return -1;
		}
	}

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION,
			NULL, NULL, NULL, NULL );
		return -1;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* modify indexes */
	if ( index_add_mods( be, modlist, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		return -1;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	return 0;

}/* int ldbm_modify_internal() */


int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );

	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);

	/* acquire and lock entry */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( -1 );
	}

    if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		goto error_return;
	}
	
	/* Modify the entry */
	if ( ldbm_modify_internal( be, conn, op, dn, modlist, e ) != 0 ) {
		goto error_return;
	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	cache_return_entry_w( &li->li_cache, e );
	return( 0 );

error_return:;
	cache_return_entry_w( &li->li_cache, e );
	return( -1 );
}

int
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

int
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

			/* delete the entire attribute, if no values remain */
			if ( a->a_vals[0] == NULL) {
				Debug( LDAP_DEBUG_ARGS,
					"removing entire attribute %s\n",
					mod->mod_type, 0, 0 );
				if ( attr_delete( &e->e_attrs, mod->mod_type ) ) {
					return LDAP_NO_SUCH_ATTRIBUTE;
				}
			}

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

int
replace_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{

	/* XXX: BEFORE YOU GET RID OF PREVIOUS VALUES REMOVE FROM INDEX
	 * FILES
	 */

	(void) attr_delete( &e->e_attrs, mod->mod_type );

	if ( attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 ) {
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}

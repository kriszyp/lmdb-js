/* modify.c - ldbm backend modify routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

static int	add_values(Entry *e, LDAPMod *mod, char *dn);
static int	delete_values(Entry *e, LDAPMod *mod, char *dn);
static int	replace_values(Entry *e, LDAPMod *mod, char *dn);
static void	add_lastmods(Operation *op, LDAPMod **mods);


static void
add_lastmods( Operation *op, LDAPMod **mods )
{
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	LDAPMod		**m;
	LDAPMod		*tmp;
	struct tm	*ltm;

	Debug( LDAP_DEBUG_TRACE, "add_lastmods\n", 0, 0, 0 );

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to modify these attrs */
	for ( m = mods; *m != NULL; m = &(*m)->mod_next ) {
            if ( strcasecmp( (*m)->mod_type, "modifytimestamp" ) == 0 || 
				strcasecmp( (*m)->mod_type, "modifiersname" ) == 0 ||
				strcasecmp( (*m)->mod_type, "createtimestamp" ) == 0 || 
				strcasecmp( (*m)->mod_type, "creatorsname" ) == 0 ) {

                Debug( LDAP_DEBUG_TRACE,
					"add_lastmods: found lastmod attr: %s\n",
					(*m)->mod_type, 0, 0 );
                tmp = *m;
                *m = (*m)->mod_next;
                free( tmp->mod_type );
                if ( tmp->mod_bvalues != NULL ) {
                    ber_bvecfree( tmp->mod_bvalues );
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
	tmp = (LDAPMod *) ch_calloc( 1, sizeof(LDAPMod) );
	tmp->mod_type = ch_strdup( "modifiersname" );
	tmp->mod_op = LDAP_MOD_REPLACE;
	tmp->mod_bvalues = (struct berval **) ch_calloc( 1,
	    2 * sizeof(struct berval *) );
	tmp->mod_bvalues[0] = ber_bvdup( &bv );
	tmp->mod_next = *mods;
	*mods = tmp;

	ldap_pvt_thread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &currenttime_mutex );
	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );
	tmp = (LDAPMod *) ch_calloc( 1, sizeof(LDAPMod) );
	tmp->mod_type = ch_strdup( "modifytimestamp" );
	tmp->mod_op = LDAP_MOD_REPLACE;
	tmp->mod_bvalues = (struct berval **) ch_calloc( 1, 2 * sizeof(struct berval *) );
	tmp->mod_bvalues[0] = ber_bvdup( &bv );
	tmp->mod_next = *mods;
	*mods = tmp;
}

/* We need this function because of LDAP modrdn. If we do not 
 * add this there would be a bunch of code replication here 
 * and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 */ 

int ldbm_internal_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPMod	*mods,
    Entry	*e 
)
{
	int		i, err;
	LDAPMod		*mod;
	Attribute	*a;
	Attribute	*save_attrs;

	if ( ((be->be_lastmod == ON)
	      || ((be->be_lastmod == UNDEFINED)&&(global_lastmod == ON)))
	     && (be->be_update_ndn == NULL)) {

		/* XXX: It may be wrong, it changes mod time even if 
		 * mod fails! I also Think this is leaking memory...
		 */
		add_lastmods( op, &mods );

	}

	if ( (err = acl_check_mods( be, conn, op, e, mods )) != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, err, NULL, NULL );
		return -1;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
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
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err, NULL, NULL );
			return -1;
		}
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, NULL, NULL );
		return -1;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* remove old indices */
	if( save_attrs != NULL ) {
		for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
			if( ( mod->mod_op & ~LDAP_MOD_BVALUES )
				== LDAP_MOD_REPLACE )
			{
				/* Need to remove all values from indexes */
				a = attr_find( save_attrs, mod->mod_type );

				if( a != NULL ) {
					(void) index_change_values( be,
						mod->mod_type,
						a->a_vals,
						e->e_id,
						__INDEX_DEL_OP);
				}

			}
		}
		attrs_free( save_attrs );
	}

	/* modify indexes */
	if ( index_add_mods( be, mods, e->e_id ) != 0 ) {
		/* our indices are likely hosed */
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL );
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
}


int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPMod	*mods
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched;
	Entry		*e;

	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);

	/* acquire and lock entry */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched,
		    NULL );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	/* Modify the entry */
	if ( ldbm_internal_modify( be, conn, op, dn, mods, e ) != 0 ) {

		goto error_return;

	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		return -1;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	cache_return_entry_w( &li->li_cache, e );
	return( 0 );

error_return:;
	cache_return_entry_w( &li->li_cache, e );
	return( -1 );
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

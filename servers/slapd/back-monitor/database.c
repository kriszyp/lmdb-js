/* database.c - deals with database subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-monitor.h"

#if defined(LDAP_SLAPI)
#include "slapi.h"
static int monitor_back_add_plugin( Backend *be, Entry *e );
#endif /* defined(LDAP_SLAPI) */

#if defined(SLAPD_LDAP) 
#include "../back-ldap/back-ldap.h"
#endif /* defined(SLAPD_LDAP) */

static struct restricted_ops_t {
	struct berval	op;
	unsigned int	tag;
} restricted_ops[] = {
	{ BER_BVC( "add" ),			SLAP_RESTRICT_OP_ADD },
	{ BER_BVC( "bind" ),			SLAP_RESTRICT_OP_BIND },
	{ BER_BVC( "compare" ),			SLAP_RESTRICT_OP_COMPARE },
	{ BER_BVC( "delete" ),			SLAP_RESTRICT_OP_DELETE },
	{ BER_BVC( "extended" ),		SLAP_RESTRICT_OP_EXTENDED },
	{ BER_BVC( "modify" ),			SLAP_RESTRICT_OP_MODIFY },
	{ BER_BVC( "rename" ),			SLAP_RESTRICT_OP_RENAME },
	{ BER_BVC( "search" ),			SLAP_RESTRICT_OP_SEARCH },
	{ BER_BVNULL,				0 }
}, restricted_exops[] = {
	{ BER_BVC( LDAP_EXOP_START_TLS ),	SLAP_RESTRICT_EXOP_START_TLS },
	{ BER_BVC( LDAP_EXOP_MODIFY_PASSWD ),	SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
	{ BER_BVC( LDAP_EXOP_X_WHO_AM_I ),	SLAP_RESTRICT_EXOP_WHOAMI },
	{ BER_BVC( LDAP_EXOP_X_CANCEL ),	SLAP_RESTRICT_EXOP_CANCEL },
	{ BER_BVNULL,				0 }
};

static int
init_readOnly( struct monitorinfo *mi, Entry *e, slap_mask_t restrictops )
{
	struct berval	*tf = ( ( restrictops & SLAP_RESTRICT_OP_MASK ) == SLAP_RESTRICT_OP_WRITES ) ?
		(struct berval *)&slap_true_bv : (struct berval *)&slap_false_bv;

	return attr_merge_one( e, mi->mi_ad_readOnly, tf, NULL );
}

static int
init_restrictedOperation( struct monitorinfo *mi, Entry *e, slap_mask_t restrictops )
{
	int	i, rc;

	for ( i = 0; restricted_ops[ i ].op.bv_val; i++ ) {
		if ( restrictops & restricted_ops[ i ].tag ) {
			rc = attr_merge_one( e, mi->mi_ad_restrictedOperation,
					&restricted_ops[ i ].op, NULL );
			if ( rc ) {
				return rc;
			}
		}
	}

	for ( i = 0; restricted_exops[ i ].op.bv_val; i++ ) {
		if ( restrictops & restricted_exops[ i ].tag ) {
			rc = attr_merge_one( e, mi->mi_ad_restrictedOperation,
					&restricted_exops[ i ].op, NULL );
			if ( rc ) {
				return rc;
			}
		}
	}

	return LDAP_SUCCESS;
}

int
monitor_subsys_database_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e_database, **ep;
	int			i;
	struct monitorentrypriv	*mp;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				&monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn, 
				&e_database ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_database_init: "
			"unable to get entry \"%s\"\n",
			monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	(void)init_readOnly( mi, e_database, frontendDB->be_restrictops );
	(void)init_restrictedOperation( mi, e_database, frontendDB->be_restrictops );

	mp = ( struct monitorentrypriv * )e_database->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	for ( i = 0; i < nBackendDB; i++ ) {
		char		buf[ BACKMONITOR_BUFSIZE ];
		int		j;
		slap_overinfo	*oi = NULL;
		BackendInfo	*bi;
		Entry		*e;

		be = &backendDB[i];

		bi = be->bd_info;

		if ( strcmp( be->bd_info->bi_type, "over" ) == 0 ) {
			oi = (slap_overinfo *)be->bd_info->bi_private;
			bi = oi->oi_orig;
		}

		/* Subordinates are not exposed as their own naming context */
		if ( SLAP_GLUE_SUBORDINATE( be ) ) {
			continue;
		}

		snprintf( buf, sizeof( buf ),
				"dn: cn=Database %d,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: Database %d\n"
				"description: This object contains the type of the database.\n"
				"%s: %s\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				i,
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_dn.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				i,
				mi->mi_ad_monitoredInfo->ad_cname.bv_val,
				bi->bi_type,
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to create entry \"cn=Database %d,%s\"\n",
				i, monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn.bv_val, 0 );
			return( -1 );
		}
		
		if ( SLAP_MONITOR(be) ) {
			attr_merge( e, slap_schema.si_ad_monitorContext,
					be->be_suffix, be->be_nsuffix );
			attr_merge( e_database, slap_schema.si_ad_monitorContext,
					be->be_suffix, be->be_nsuffix );
		} else {
			attr_merge( e, slap_schema.si_ad_namingContexts,
					be->be_suffix, be->be_nsuffix );
			attr_merge( e_database, slap_schema.si_ad_namingContexts,
					be->be_suffix, be->be_nsuffix );
		}

		(void)init_readOnly( mi, e, be->be_restrictops );
		(void)init_restrictedOperation( mi, e, be->be_restrictops );

		if ( oi != NULL ) {
			slap_overinst *on = oi->oi_list;

			for ( ; on; on = on->on_next ) {
				struct berval		bv;
				slap_overinst		*on2;
				
				bv.bv_val = on->on_bi.bi_type;
				bv.bv_len = strlen( bv.bv_val );
				attr_merge_normalize_one( e, mi->mi_ad_monitorOverlay,
						&bv, NULL );

				for ( on2 = overlay_next( NULL ), j = 0; on2; on2 = overlay_next( on2 ), j++ ) {
					if ( on2->on_bi.bi_type == on->on_bi.bi_type ) {
						break;
					}
				}
				assert( on2 );

				snprintf( buf, sizeof( buf ), 
					"cn=Overlay %d,%s", 
					j, monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_dn.bv_val );
				bv.bv_val = buf;
				bv.bv_len = strlen( buf );
				attr_merge_normalize_one( e, mi->mi_ad_seeAlso,
						&bv, NULL );
			}
		}

#if defined(SLAPD_LDAP) 
		if ( strcmp( bi->bi_type, "ldap" ) == 0 ) {
			struct ldapinfo		*li = (struct ldapinfo *)be->be_private;
			struct berval		bv;

			bv.bv_val = li->url;
			bv.bv_len = strlen( bv.bv_val );
			attr_merge_normalize_one( e, mi->mi_ad_labeledURI,
					&bv, NULL );
		}
#endif /* defined(SLAPD_LDAP) */

		for ( j = 0; j < nBackendInfo; j++ ) {
			if ( backendInfo[ j ].bi_type == bi->bi_type ) {
				struct berval 		bv;

				snprintf( buf, sizeof( buf ), 
					"cn=Backend %d,%s", 
					j, monitor_subsys[SLAPD_MONITOR_BACKEND].mss_dn.bv_val );
				bv.bv_val = buf;
				bv.bv_len = strlen( buf );
				attr_merge_normalize_one( e, mi->mi_ad_seeAlso,
						&bv, NULL );
				break;
			}
		}
		/* we must find it! */
		assert( j >= 0 );

		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = NULL;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_DATABASE];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_DATABASE].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to add entry \"cn=Database %d,%s\"\n",
				i, monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn.bv_val, 0 );
			return( -1 );
		}

#if defined(LDAP_SLAPI)
		monitor_back_add_plugin( be, e );
#endif /* defined(LDAP_SLAPI) */

		*ep = e;
		ep = &mp->mp_next;
	}
	
	monitor_cache_release( mi, e_database );

	return( 0 );
}

/*
 * v: array of values
 * cur: must not contain the tags corresponding to the values in v
 * delta: will contain the tags corresponding to the values in v
 */
static int
value_mask( BerVarray v, slap_mask_t cur, slap_mask_t *delta )
{
	for ( ; !BER_BVISNULL( v ); v++ ) {
		struct restricted_ops_t		*rops;
		int				i;

		if ( OID_LEADCHAR( v->bv_val[ 0 ] ) ) {
			rops = restricted_exops;

		} else {
			rops = restricted_ops;
		}

		for ( i = 0; !BER_BVISNULL( &rops[ i ].op ); i++ ) {
			if ( ber_bvstrcasecmp( v, &rops[ i ].op ) != 0 ) {
				continue;
			}

			if ( rops[ i ].tag & *delta ) {
				return LDAP_OTHER;
			}

			if ( rops[ i ].tag & cur ) {
				return LDAP_OTHER;
			}

			cur |= rops[ i ].tag;
			*delta |= rops[ i ].tag;

			break;
		}

		if ( BER_BVISNULL( &rops[ i ].op ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

int
monitor_subsys_database_modify(
	Operation	*op,
	Entry		*e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	int rc = LDAP_OTHER;
	Attribute *save_attrs, *a;
	Modifications *modlist = op->oq_modify.rs_modlist;
	Modifications *ml;
	Backend *be;
	int ro_gotval = 1, i, n;
	slap_mask_t	rp_add = 0, rp_delete = 0, rp_cur;
	struct berval *tf;
	
	i = sscanf( e->e_nname.bv_val, "cn=database %d,", &n );
	if ( i != 1 )
		return LDAP_UNWILLING_TO_PERFORM;

	if ( n < 0 || n >= nBackendDB )
		return LDAP_NO_SUCH_OBJECT;

	/* do not allow some changes on back-monitor (needs work)... */
	be = &backendDB[n];
	if ( SLAP_MONITOR( be ) )
		return LDAP_UNWILLING_TO_PERFORM;
		
	rp_cur = be->be_restrictops;

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml=modlist; ml; ml=ml->sml_next ) {
		Modification *mod = &ml->sml_mod;

		if ( mod->sm_desc == mi->mi_ad_readOnly ) {
			int	val = -1;

			if ( mod->sm_values ) {
				if ( !BER_BVISNULL( &mod->sm_values[ 1 ] ) ) {
					rc = LDAP_CONSTRAINT_VIOLATION;
					goto done;
				}

				if ( bvmatch( &slap_true_bv, mod->sm_values )) {
					val = 1;

				} else if ( bvmatch( &slap_false_bv, mod->sm_values )) {
					val = 0;

				} else {
					rc = LDAP_INVALID_SYNTAX;
					goto done;
				}
			}

			switch ( mod->sm_op ) {
			case LDAP_MOD_DELETE:
				if ( ro_gotval < 1 ) {
					rc = LDAP_CONSTRAINT_VIOLATION;
					goto done;
				}
				ro_gotval--;

				if ( val == 0 && ( rp_cur & SLAP_RESTRICT_OP_WRITES ) == SLAP_RESTRICT_OP_WRITES ) {
					rc = LDAP_NO_SUCH_ATTRIBUTE;
					goto done;
				}
				
				if ( val == 1 && ( rp_cur & SLAP_RESTRICT_OP_WRITES ) != SLAP_RESTRICT_OP_WRITES ) {
					rc = LDAP_NO_SUCH_ATTRIBUTE;
					goto done;
				}
				
				break;

			case LDAP_MOD_REPLACE:
				ro_gotval = 0;
				/* fall thru */

			case LDAP_MOD_ADD:
				if ( ro_gotval > 0 ) {
					rc = LDAP_CONSTRAINT_VIOLATION;
					goto done;
				}
				ro_gotval++;

				if ( val == 1 ) {
					rp_add |= (~rp_cur) & SLAP_RESTRICT_OP_WRITES;
					rp_cur |= SLAP_RESTRICT_OP_WRITES;
					rp_delete &= ~SLAP_RESTRICT_OP_WRITES;
					
				} else if ( val == 0 ) {
					rp_delete |= rp_cur & SLAP_RESTRICT_OP_WRITES;
					rp_cur &= ~SLAP_RESTRICT_OP_WRITES;
					rp_add &= ~SLAP_RESTRICT_OP_WRITES;
				}
				break;

			default:
				rc = LDAP_OTHER;
				goto done;
			}

		} else if ( mod->sm_desc == mi->mi_ad_restrictedOperation ) {
			slap_mask_t	mask = 0;

			switch ( mod->sm_op ) {
			case LDAP_MOD_DELETE:
				if ( mod->sm_values == NULL ) {
					rp_delete = rp_cur;
					rp_cur = 0;
					rp_add = 0;
					break;
				}
				rc = value_mask( mod->sm_values, ~rp_cur, &mask );
				if ( rc == LDAP_SUCCESS ) {
					rp_delete |= mask;
					rp_add &= ~mask;
					rp_cur &= ~mask;

				} else if ( rc == LDAP_OTHER ) {
					rc = LDAP_NO_SUCH_ATTRIBUTE;
				}
				break;

			case LDAP_MOD_REPLACE:
				rp_delete = rp_cur;
				rp_cur = 0;
				rp_add = 0;
				/* fall thru */

			case LDAP_MOD_ADD:
				rc = value_mask( mod->sm_values, rp_cur, &mask );
				if ( rc == LDAP_SUCCESS ) {
					rp_add |= mask;
					rp_cur |= mask;
					rp_delete &= ~mask;

				} else if ( rc == LDAP_OTHER ) {
					rc = LDAP_TYPE_OR_VALUE_EXISTS;
				}
				break;

			default:
				rc = LDAP_OTHER;
				break;
			}

			if ( rc != LDAP_SUCCESS ) {
				goto done;
			}

		} else if ( is_at_operational( mod->sm_desc->ad_type )) {
		/* accept all operational attributes */
			attr_delete( &e->e_attrs, mod->sm_desc );
			rc = attr_merge( e, mod->sm_desc, mod->sm_values,
				mod->sm_nvalues );
			if ( rc ) {
				rc = LDAP_OTHER;
				break;
			}

		} else {
			rc = LDAP_UNWILLING_TO_PERFORM;
			break;
		}
	}

	/* sanity checks: */
	if ( ro_gotval < 1 ) {
		rc = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

	if ( ( rp_cur & SLAP_RESTRICT_OP_EXTENDED ) && ( rp_cur & SLAP_RESTRICT_EXOP_MASK ) ) {
		rc = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

	if ( rp_delete & rp_add ) {
		rc = LDAP_OTHER;
		goto done;
	}

	/* check current value of readOnly */
	if ( ( rp_cur & SLAP_RESTRICT_OP_WRITES ) == SLAP_RESTRICT_OP_WRITES ) {
		tf = (struct berval *)&slap_true_bv;

	} else {
		tf = (struct berval *)&slap_false_bv;
	}

	a = attr_find( e->e_attrs, mi->mi_ad_readOnly );
	if ( a == NULL ) {
		rc = LDAP_OTHER;
		goto done;
	}

	if ( !bvmatch( &a->a_vals[0], tf ) ) {
		attr_delete( &e->e_attrs, mi->mi_ad_readOnly );
		rc = attr_merge_one( e, mi->mi_ad_readOnly, tf, NULL );
	}

	if ( rc == LDAP_SUCCESS ) {
		if ( rp_delete ) {
			if ( rp_delete == be->be_restrictops ) {
				attr_delete( &e->e_attrs, mi->mi_ad_restrictedOperation );

			} else {
				a = attr_find( e->e_attrs, mi->mi_ad_restrictedOperation );
				if ( a == NULL ) {
					rc = LDAP_OTHER;
					goto done;
				}

				for ( i = 0; !BER_BVISNULL( &restricted_ops[ i ].op ); i++ ) {
					if ( rp_delete & restricted_ops[ i ].tag ) {
						int	j;
					
						for ( j = 0; !BER_BVISNULL( &a->a_nvals[ j ] ); j++ ) {
							int		k;

							if ( !bvmatch( &a->a_nvals[ j ], &restricted_ops[ i ].op ) ) {
								continue;
							}

							ch_free( a->a_vals[ j ].bv_val );
							ch_free( a->a_nvals[ j ].bv_val );

							for ( k = j + 1; !BER_BVISNULL( &a->a_nvals[ k ] ); k++ ) {
								a->a_vals[ k - 1 ] = a->a_vals[ k ];
								a->a_nvals[ k - 1 ] = a->a_nvals[ k ];
							}
	
							BER_BVZERO( &a->a_vals[ k - 1 ] );
							BER_BVZERO( &a->a_nvals[ k - 1 ] );
						}
					}
				}
				
				for ( i = 0; !BER_BVISNULL( &restricted_exops[ i ].op ); i++ ) {
					if ( rp_delete & restricted_exops[ i ].tag ) {
						int	j;
					
						for ( j = 0; !BER_BVISNULL( &a->a_nvals[ j ] ); j++ ) {
							int		k;

							if ( !bvmatch( &a->a_nvals[ j ], &restricted_exops[ i ].op ) ) {
								continue;
							}

							ch_free( a->a_vals[ j ].bv_val );
							ch_free( a->a_nvals[ j ].bv_val );

							for ( k = j + 1; !BER_BVISNULL( &a->a_nvals[ k ] ); k++ ) {
								a->a_vals[ k - 1 ] = a->a_vals[ k ];
								a->a_nvals[ k - 1 ] = a->a_nvals[ k ];
							}
	
							BER_BVZERO( &a->a_vals[ k - 1 ] );
							BER_BVZERO( &a->a_nvals[ k - 1 ] );
						}
					}
				}
			}
		}

		if ( rp_add ) {
			for ( i = 0; !BER_BVISNULL( &restricted_ops[ i ].op ); i++ ) {
				if ( rp_add & restricted_ops[ i ].tag ) {
					attr_merge_one( e, mi->mi_ad_restrictedOperation,
							&restricted_ops[ i ].op, NULL );
				}
			}

			for ( i = 0; !BER_BVISNULL( &restricted_exops[ i ].op ); i++ ) {
				if ( rp_add & restricted_exops[ i ].tag ) {
					attr_merge_one( e, mi->mi_ad_restrictedOperation,
							&restricted_exops[ i ].op, NULL );
				}
			}
		}
	}

	be->be_restrictops = rp_cur;

done:;
	if ( rc == LDAP_SUCCESS ) {
		attrs_free( save_attrs );

	} else {
		Attribute *tmp = e->e_attrs;
		e->e_attrs = save_attrs;
		attrs_free( tmp );
	}
	return rc;
}

#if defined(LDAP_SLAPI)
static int
monitor_back_add_plugin( Backend *be, Entry *e_database )
{
	Slapi_PBlock		*pCurrentPB; 
	int			i, rc = LDAP_SUCCESS;
	struct monitorinfo	*mi = ( struct monitorinfo * )be->be_private;

	if ( slapi_int_pblock_get_first( be, &pCurrentPB ) != LDAP_SUCCESS ) {
		/*
		 * LDAP_OTHER is returned if no plugins are installed
		 */
		rc = LDAP_OTHER;
		goto done;
	}

	i = 0;
	do {
		Slapi_PluginDesc	*srchdesc;
		char			buf[ BACKMONITOR_BUFSIZE ];
		struct berval		bv;

		rc = slapi_pblock_get( pCurrentPB, SLAPI_PLUGIN_DESCRIPTION,
				&srchdesc );
		if ( rc != LDAP_SUCCESS ) {
			goto done;
		}

		snprintf( buf, sizeof(buf),
				"plugin %d name: %s; "
				"vendor: %s; "
				"version: %s; "
				"description: %s", 
				i,
				srchdesc->spd_id,
				srchdesc->spd_vendor,
				srchdesc->spd_version,
				srchdesc->spd_description );

		bv.bv_val = buf;
		bv.bv_len = strlen( buf );
		attr_merge_normalize_one( e_database,
				mi->mi_ad_monitoredInfo, &bv, NULL );

		i++;

	} while ( ( slapi_int_pblock_get_next( &pCurrentPB ) == LDAP_SUCCESS )
			&& ( pCurrentPB != NULL ) );

done:
	return rc;
}
#endif /* defined(LDAP_SLAPI) */

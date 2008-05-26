/* database.c - deals with database subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2008 The OpenLDAP Foundation.
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
#include <ac/unistd.h>

#include "slap.h"
#include "back-monitor.h"

#if defined(LDAP_SLAPI)
#include "slapi.h"
static int monitor_back_add_plugin( monitor_info_t *mi, Backend *be, Entry *e );
#endif /* defined(LDAP_SLAPI) */

#if defined(SLAPD_BDB)
#include "../back-bdb/back-bdb.h"
#endif /* defined(SLAPD_BDB) */
#if defined(SLAPD_HDB)
#include "../back-hdb/back-bdb.h"
#endif /* defined(SLAPD_HDB) */
#if defined(SLAPD_LDAP) 
#include "../back-ldap/back-ldap.h"
#endif /* defined(SLAPD_LDAP) */
#if 0 && defined(SLAPD_LDBM) 
#include "../back-ldbm/back-ldbm.h"
#endif /* defined(SLAPD_LDBM) */
#if defined(SLAPD_META) 
#include "../back-meta/back-meta.h"
#endif /* defined(SLAPD_META) */

static int
monitor_subsys_database_modify(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e );

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
init_readOnly( monitor_info_t *mi, Entry *e, slap_mask_t restrictops )
{
	struct berval	*tf = ( ( restrictops & SLAP_RESTRICT_OP_MASK ) == SLAP_RESTRICT_OP_WRITES ) ?
		(struct berval *)&slap_true_bv : (struct berval *)&slap_false_bv;

	return attr_merge_one( e, mi->mi_ad_readOnly, tf, tf );
}

static int
init_restrictedOperation( monitor_info_t *mi, Entry *e, slap_mask_t restrictops )
{
	int	i, rc;

	for ( i = 0; restricted_ops[ i ].op.bv_val; i++ ) {
		if ( restrictops & restricted_ops[ i ].tag ) {
			rc = attr_merge_one( e, mi->mi_ad_restrictedOperation,
					&restricted_ops[ i ].op,
					&restricted_ops[ i ].op );
			if ( rc ) {
				return rc;
			}
		}
	}

	for ( i = 0; restricted_exops[ i ].op.bv_val; i++ ) {
		if ( restrictops & restricted_exops[ i ].tag ) {
			rc = attr_merge_one( e, mi->mi_ad_restrictedOperation,
					&restricted_exops[ i ].op,
					&restricted_exops[ i ].op );
			if ( rc ) {
				return rc;
			}
		}
	}

	return LDAP_SUCCESS;
}

int
monitor_subsys_database_init(
	BackendDB		*be,
	monitor_subsys_t	*ms
)
{
	monitor_info_t		*mi;
	Entry			*e_database, **ep;
	int			i;
	monitor_entry_t		*mp;
	monitor_subsys_t	*ms_backend,
				*ms_overlay;

	assert( be != NULL );

	ms->mss_modify = monitor_subsys_database_modify;

	mi = ( monitor_info_t * )be->be_private;

	ms_backend = monitor_back_get_subsys( SLAPD_MONITOR_BACKEND_NAME );
	if ( ms_backend == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_database_init: "
			"unable to get "
			"\"" SLAPD_MONITOR_BACKEND_NAME "\" "
			"subsystem\n",
			0, 0, 0 );
		return -1;
	}

	ms_overlay = monitor_back_get_subsys( SLAPD_MONITOR_OVERLAY_NAME );
	if ( ms_overlay == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_database_init: "
			"unable to get "
			"\"" SLAPD_MONITOR_OVERLAY_NAME "\" "
			"subsystem\n",
			0, 0, 0 );
		return -1;
	}

	if ( monitor_cache_get( mi, &ms->mss_ndn, &e_database ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_database_init: "
			"unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	(void)init_readOnly( mi, e_database, frontendDB->be_restrictops );
	(void)init_restrictedOperation( mi, e_database, frontendDB->be_restrictops );

	mp = ( monitor_entry_t * )e_database->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	i = -1;
	LDAP_STAILQ_FOREACH( be, &backendDB, be_next ) {
		char		buf[ BACKMONITOR_BUFSIZE ];
		int		j;
		slap_overinfo	*oi = NULL;
		BackendInfo	*bi, *bi2;
		Entry		*e;

		i++;

		bi = be->bd_info;

		if ( overlay_is_over( be ) ) {
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
				"%s: %s\n"
				"%s: %s\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				i,
					ms->mss_dn.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				i,
				mi->mi_ad_monitoredInfo->ad_cname.bv_val,
					bi->bi_type,
				mi->mi_ad_monitorIsShadow->ad_cname.bv_val,
					SLAP_SHADOW( be ) ? slap_true_bv.bv_val : slap_false_bv.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to create entry \"cn=Database %d,%s\"\n",
				i, ms->mss_dn.bv_val, 0 );
			return( -1 );
		}
		
		if ( SLAP_MONITOR( be ) ) {
			attr_merge( e, slap_schema.si_ad_monitorContext,
					be->be_suffix, be->be_nsuffix );
			attr_merge( e_database, slap_schema.si_ad_monitorContext,
					be->be_suffix, be->be_nsuffix );

		} else {
			if ( be->be_suffix == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"monitor_subsys_database_init: "
					"missing suffix for database %d\n",
					i, 0, 0 );
				return -1;
			}
			attr_merge( e, slap_schema.si_ad_namingContexts,
					be->be_suffix, be->be_nsuffix );
			attr_merge( e_database, slap_schema.si_ad_namingContexts,
					be->be_suffix, be->be_nsuffix );
		}

		(void)init_readOnly( mi, e, be->be_restrictops );
		(void)init_restrictedOperation( mi, e, be->be_restrictops );

		if ( SLAP_SHADOW( be ) && be->be_update_refs ) {
			attr_merge_normalize( e, mi->mi_ad_monitorUpdateRef,
					be->be_update_refs, NULL );
		}

		if ( oi != NULL ) {
			slap_overinst	*on = oi->oi_list,
					*on1 = on;

			for ( ; on; on = on->on_next ) {
				struct berval		bv;
				slap_overinst		*on2;

				for ( on2 = on1; on2 != on; on2 = on2->on_next ) {
					if ( on2->on_bi.bi_type == on->on_bi.bi_type ) {
						break;
					}
				}

				if ( on2 != on ) {
					break;
				}
				
				ber_str2bv( on->on_bi.bi_type, 0, 0, &bv );
				attr_merge_normalize_one( e, mi->mi_ad_monitorOverlay,
						&bv, NULL );

				/* find the overlay number, j */
				for ( on2 = overlay_next( NULL ), j = 0; on2; on2 = overlay_next( on2 ), j++ ) {
					if ( on2->on_bi.bi_type == on->on_bi.bi_type ) {
						break;
					}
				}
				assert( on2 != NULL );

				snprintf( buf, sizeof( buf ), 
					"cn=Overlay %d,%s", 
					j, ms_overlay->mss_dn.bv_val );
				ber_str2bv( buf, 0, 0, &bv );
				attr_merge_normalize_one( e,
						slap_schema.si_ad_seeAlso,
						&bv, NULL );
			}
		}


		if ( 0 ) {
			assert( 0 );

#if defined(SLAPD_BDB) || defined(SLAPD_HDB) 
		} else if ( strcmp( bi->bi_type, "bdb" ) == 0
				|| strcmp( bi->bi_type, "hdb" ) == 0 )
		{
			struct berval	bv;
			ber_len_t	pathlen = 0, len = 0;
			char		path[ MAXPATHLEN ] = { '\0' };
			struct bdb_info *bdb = (struct bdb_info *) be->be_private;
			char		*fname = bdb->bi_dbenv_home;

			len = strlen( fname );
			if ( fname[ 0 ] != '/' ) {
				/* get full path name */
				getcwd( path, sizeof( path ) );
				pathlen = strlen( path );

				if ( fname[ 0 ] == '.' && fname[ 1 ] == '/' ) {
					fname += 2;
					len -= 2;
				}
			}

			bv.bv_len = STRLENOF( "file://" ) + pathlen
				+ STRLENOF( "/" ) + len;
			bv.bv_val = ch_malloc( bv.bv_len + STRLENOF( "/" ) + 1 );
			AC_MEMCPY( bv.bv_val, "file://", STRLENOF( "file://" ) );
			if ( pathlen ) {
				AC_MEMCPY( &bv.bv_val[ STRLENOF( "file://" ) ],
						path, pathlen );
				bv.bv_val[ STRLENOF( "file://" ) + pathlen ] = '/';
				pathlen++;
			}
			AC_MEMCPY( &bv.bv_val[ STRLENOF( "file://" ) + pathlen ],
					fname, len );
			if ( bv.bv_val[ bv.bv_len - 1 ] != '/' ) {
				bv.bv_val[ bv.bv_len ] = '/';
				bv.bv_len++;
			}
			bv.bv_val[ bv.bv_len ] = '\0';

			attr_merge_normalize_one( e, slap_schema.si_ad_labeledURI,
					&bv, NULL );

			ch_free( bv.bv_val );

#endif /* defined(SLAPD_BDB) || defined(SLAPD_HDB) */
#if defined(SLAPD_LDAP) 
		} else if ( strcmp( bi->bi_type, "ldap" ) == 0 ) {
			ldapinfo_t	*li = (ldapinfo_t *)be->be_private;
#if 0
			attr_merge_normalize( e, slap_schema.si_ad_labeledURI,
					li->li_bvuri, NULL );
#else
			char		**urls = ldap_str2charray( li->li_uri, " " );
			int		u;

			for ( u = 0; urls[ u ] != NULL; u++ ) {
				struct berval	bv;

				ber_str2bv( urls[ u ], 0, 0, &bv );

				attr_merge_normalize_one( e,
						slap_schema.si_ad_labeledURI,
						&bv, NULL );
			}

			ldap_charray_free( urls );
#endif

#endif /* defined(SLAPD_LDAP) */
#if defined(SLAPD_META) 
		} else if ( strcmp( bi->bi_type, "meta" ) == 0 ) {
			metainfo_t	*mi = (metainfo_t *)be->be_private;
			int		t;

			for ( t = 0; t < mi->mi_ntargets; t++ ) {
				char		**urls = ldap_str2charray( mi->mi_targets[ t ]->mt_uri, " " );
				int		u;

				for ( u = 0; urls[ u ] != NULL; u++ ) {
					struct berval	bv;

					ber_str2bv( urls[ u ], 0, 0, &bv );

					attr_merge_normalize_one( e,
						slap_schema.si_ad_labeledURI,
						&bv, NULL );
				}
				ldap_charray_free( urls );
			}
#endif /* defined(SLAPD_META) */
		}

		j = -1;
		LDAP_STAILQ_FOREACH( bi2, &backendInfo, bi_next ) {
			j++;
			if ( bi2->bi_type == bi->bi_type ) {
				struct berval 		bv;

				snprintf( buf, sizeof( buf ), 
					"cn=Backend %d,%s", 
					j, ms_backend->mss_dn.bv_val );
				bv.bv_val = buf;
				bv.bv_len = strlen( buf );
				attr_merge_normalize_one( e,
						slap_schema.si_ad_seeAlso,
						&bv, NULL );
				break;
			}
		}
		/* we must find it! */
		assert( j >= 0 );

		mp = monitor_entrypriv_create();
		if ( mp == NULL ) {
			return -1;
		}
		e->e_private = ( void * )mp;
		mp->mp_info = ms;
		mp->mp_flags = ms->mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to add entry \"cn=Database %d,%s\"\n",
				i, ms->mss_dn.bv_val, 0 );
			return( -1 );
		}

#if defined(LDAP_SLAPI)
		monitor_back_add_plugin( mi, be, e );
#endif /* defined(LDAP_SLAPI) */

		if ( oi != NULL ) {
			Entry		**ep_overlay = &mp->mp_children;
			monitor_entry_t	*mp_overlay;
			slap_overinst	*on = oi->oi_list;
			int		o;

			for ( o = 0; on; o++, on = on->on_next ) {
				Entry			*e_overlay;
				slap_overinst		*on2;

				/* find the overlay number, j */
				for ( on2 = overlay_next( NULL ), j = 0; on2; on2 = overlay_next( on2 ), j++ ) {
					if ( on2->on_bi.bi_type == on->on_bi.bi_type ) {
						break;
					}
				}
				assert( on2 != NULL );

				snprintf( buf, sizeof( buf ),
						"dn: cn=Overlay %d,cn=Database %d,%s\n"
						"objectClass: %s\n"
						"structuralObjectClass: %s\n"
						"cn: Overlay %d\n"
						"%s: %s\n"
						"seeAlso: cn=Overlay %d,%s\n"
						"creatorsName: %s\n"
						"modifiersName: %s\n"
						"createTimestamp: %s\n"
						"modifyTimestamp: %s\n",
						o,
						i,
						ms->mss_dn.bv_val,
						mi->mi_oc_monitoredObject->soc_cname.bv_val,
						mi->mi_oc_monitoredObject->soc_cname.bv_val,
						o,
						mi->mi_ad_monitoredInfo->ad_cname.bv_val,
						on->on_bi.bi_type,
						j,
						ms_overlay->mss_dn.bv_val,
						mi->mi_creatorsName.bv_val,
						mi->mi_creatorsName.bv_val,
						mi->mi_startTime.bv_val,
						mi->mi_startTime.bv_val );
				
				e_overlay = str2entry( buf );
				if ( e_overlay == NULL ) {
					Debug( LDAP_DEBUG_ANY,
						"monitor_subsys_database_init: "
						"unable to create entry "
						"\"cn=Overlay %d,cn=Database %d,%s\"\n",
						o, i, ms->mss_dn.bv_val );
					return( -1 );
				}

				mp_overlay = monitor_entrypriv_create();
				if ( mp_overlay == NULL ) {
					return -1;
				}
				e_overlay->e_private = ( void * )mp_overlay;
				mp_overlay->mp_info = ms;
				mp_overlay->mp_flags = ms->mss_flags
					| MONITOR_F_SUB;
		
				if ( monitor_cache_add( mi, e_overlay ) ) {
					Debug( LDAP_DEBUG_ANY,
						"monitor_subsys_database_init: "
						"unable to add entry "
						"\"cn=Overlay %d,cn=Database %d,%s\"\n",
						o, i, ms->mss_dn.bv_val );
					return( -1 );
				}

				*ep_overlay = e_overlay;
				ep_overlay = &mp_overlay->mp_next;
			}
		}

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

static int
monitor_subsys_database_modify(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e )
{
	monitor_info_t	*mi = (monitor_info_t *)op->o_bd->be_private;
	int		rc = LDAP_OTHER;
	Attribute	*save_attrs, *a;
	Modifications	*ml;
	Backend		*be;
	int		ro_gotval = 1, i, n;
	slap_mask_t	rp_add = 0, rp_delete = 0, rp_cur;
	struct berval	*tf;
	
	i = sscanf( e->e_nname.bv_val, "cn=database %d,", &n );
	if ( i != 1 ) {
		return SLAP_CB_CONTINUE;
	}

	if ( n < 0 || n >= nBackendDB ) {
		rs->sr_text = "invalid database index";
		return ( rs->sr_err = LDAP_NO_SUCH_OBJECT );
	}

	LDAP_STAILQ_FOREACH( be, &backendDB, be_next ) {
		if ( n == 0 ) {
			break;
		}
		n--;
	}
	/* do not allow some changes on back-monitor (needs work)... */
	if ( SLAP_MONITOR( be ) ) {
		rs->sr_text = "no modifications allowed to monitor database entry";
		return ( rs->sr_err = LDAP_UNWILLING_TO_PERFORM );
	}
		
	rp_cur = be->be_restrictops;

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = op->orm_modlist; ml; ml = ml->sml_next ) {
		Modification *mod = &ml->sml_mod;

		if ( mod->sm_desc == mi->mi_ad_readOnly ) {
			int	val = -1;

			if ( mod->sm_values ) {
				if ( !BER_BVISNULL( &mod->sm_values[ 1 ] ) ) {
					rs->sr_text = "attempting to modify multiple values of single-valued attribute";
					rc = rs->sr_err = LDAP_CONSTRAINT_VIOLATION;
					goto done;
				}

				if ( bvmatch( &slap_true_bv, mod->sm_values )) {
					val = 1;

				} else if ( bvmatch( &slap_false_bv, mod->sm_values )) {
					val = 0;

				} else {
					assert( 0 );
					rc = rs->sr_err = LDAP_INVALID_SYNTAX;
					goto done;
				}
			}

			switch ( mod->sm_op ) {
			case LDAP_MOD_DELETE:
				if ( ro_gotval < 1 ) {
					rc = rs->sr_err = LDAP_CONSTRAINT_VIOLATION;
					goto done;
				}
				ro_gotval--;

				if ( val == 0 && ( rp_cur & SLAP_RESTRICT_OP_WRITES ) == SLAP_RESTRICT_OP_WRITES ) {
					rc = rs->sr_err = LDAP_NO_SUCH_ATTRIBUTE;
					goto done;
				}
				
				if ( val == 1 && ( rp_cur & SLAP_RESTRICT_OP_WRITES ) != SLAP_RESTRICT_OP_WRITES ) {
					rc = rs->sr_err = LDAP_NO_SUCH_ATTRIBUTE;
					goto done;
				}
				
				break;

			case LDAP_MOD_REPLACE:
				ro_gotval = 0;
				/* fall thru */

			case LDAP_MOD_ADD:
				if ( ro_gotval > 0 ) {
					rc = rs->sr_err = LDAP_CONSTRAINT_VIOLATION;
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
				rc = rs->sr_err = LDAP_OTHER;
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
					rc = rs->sr_err = LDAP_TYPE_OR_VALUE_EXISTS;
				}
				break;

			default:
				rc = rs->sr_err = LDAP_OTHER;
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
				rc = rs->sr_err = LDAP_OTHER;
				break;
			}

		} else {
			rc = rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			break;
		}
	}

	/* sanity checks: */
	if ( ro_gotval < 1 ) {
		rc = rs->sr_err = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

	if ( ( rp_cur & SLAP_RESTRICT_OP_EXTENDED ) && ( rp_cur & SLAP_RESTRICT_EXOP_MASK ) ) {
		rc = rs->sr_err = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

	if ( rp_delete & rp_add ) {
		rc = rs->sr_err = LDAP_OTHER;
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

	if ( !bvmatch( &a->a_vals[ 0 ], tf ) ) {
		attr_delete( &e->e_attrs, mi->mi_ad_readOnly );
		rc = attr_merge_one( e, mi->mi_ad_readOnly, tf, tf );
	}

	if ( rc == LDAP_SUCCESS ) {
		if ( rp_delete ) {
			if ( rp_delete == be->be_restrictops ) {
				attr_delete( &e->e_attrs, mi->mi_ad_restrictedOperation );

			} else {
				a = attr_find( e->e_attrs, mi->mi_ad_restrictedOperation );
				if ( a == NULL ) {
					rc = rs->sr_err = LDAP_OTHER;
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
							&restricted_ops[ i ].op,
							&restricted_ops[ i ].op );
				}
			}

			for ( i = 0; !BER_BVISNULL( &restricted_exops[ i ].op ); i++ ) {
				if ( rp_add & restricted_exops[ i ].tag ) {
					attr_merge_one( e, mi->mi_ad_restrictedOperation,
							&restricted_exops[ i ].op,
							&restricted_exops[ i ].op );
				}
			}
		}
	}

	be->be_restrictops = rp_cur;

done:;
	if ( rc == LDAP_SUCCESS ) {
		attrs_free( save_attrs );
		rc = SLAP_CB_CONTINUE;

	} else {
		Attribute *tmp = e->e_attrs;
		e->e_attrs = save_attrs;
		attrs_free( tmp );
	}
	return rc;
}

#if defined(LDAP_SLAPI)
static int
monitor_back_add_plugin( monitor_info_t *mi, Backend *be, Entry *e_database )
{
	Slapi_PBlock	*pCurrentPB; 
	int		i, rc = LDAP_SUCCESS;

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

		ber_str2bv( buf, 0, 0, &bv );
		attr_merge_normalize_one( e_database,
				mi->mi_ad_monitoredInfo, &bv, NULL );

		i++;

	} while ( ( slapi_int_pblock_get_next( &pCurrentPB ) == LDAP_SUCCESS )
			&& ( pCurrentPB != NULL ) );

done:
	return rc;
}
#endif /* defined(LDAP_SLAPI) */

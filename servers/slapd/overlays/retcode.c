/* retcode.c - customizable response for client testing purposes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2008 The OpenLDAP Foundation.
 * Portions Copyright 2005 Pierangelo Masarati <ando@sys-net.it>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_RETCODE

#include <stdio.h>

#include <ac/unistd.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "slap.h"
#include "lutil.h"

static slap_overinst		retcode;

static AttributeDescription	*ad_errCode;
static AttributeDescription	*ad_errText;
static AttributeDescription	*ad_errOp;
static AttributeDescription	*ad_errSleepTime;
static AttributeDescription	*ad_errMatchedDN;
static ObjectClass		*oc_errAbsObject;
static ObjectClass		*oc_errObject;
static ObjectClass		*oc_errAuxObject;

typedef enum retcode_op_e {
	SN_DG_OP_NONE		= 0x0000,
	SN_DG_OP_ADD		= 0x0001,
	SN_DG_OP_BIND		= 0x0002,
	SN_DG_OP_COMPARE	= 0x0004,
	SN_DG_OP_DELETE		= 0x0008,
	SN_DG_OP_MODIFY		= 0x0010,
	SN_DG_OP_RENAME		= 0x0020,
	SN_DG_OP_SEARCH		= 0x0040,
	SN_DG_EXTENDED		= 0x0080,
	SN_DG_OP_AUTH		= SN_DG_OP_BIND,
	SN_DG_OP_READ		= (SN_DG_OP_COMPARE|SN_DG_OP_SEARCH),
	SN_DG_OP_WRITE		= (SN_DG_OP_ADD|SN_DG_OP_DELETE|SN_DG_OP_MODIFY|SN_DG_OP_RENAME),
	SN_DG_OP_ALL		= (SN_DG_OP_AUTH|SN_DG_OP_READ|SN_DG_OP_WRITE|SN_DG_EXTENDED)
} retcode_op_e;

typedef struct retcode_item_t {
	struct berval		rdi_dn;
	struct berval		rdi_ndn;
	struct berval		rdi_text;
	struct berval		rdi_matched;
	int			rdi_err;
	BerVarray		rdi_ref;
	int			rdi_sleeptime;
	Entry			rdi_e;
	slap_mask_t		rdi_mask;
	struct retcode_item_t	*rdi_next;
} retcode_item_t;

typedef struct retcode_t {
	struct berval		rd_pdn;
	struct berval		rd_npdn;

	int			rd_sleep;

	retcode_item_t		*rd_item;

	unsigned		rd_flags;
#define	RETCODE_FNONE		0x00
#define	RETCODE_FINDIR		0x01
#define	RETCODE_INDIR( rd )	( (rd)->rd_flags & RETCODE_FINDIR )
} retcode_t;

static int
retcode_entry_response( Operation *op, SlapReply *rs, BackendInfo *bi, Entry *e );

static int
retcode_cleanup_cb( Operation *op, SlapReply *rs )
{
	rs->sr_matched = NULL;
	rs->sr_text = NULL;

	if ( rs->sr_ref != NULL ) {
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
	}

	ch_free( op->o_callback );
	op->o_callback = NULL;

	return SLAP_CB_CONTINUE;
}

static int
retcode_send_onelevel( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	retcode_item_t	*rdi;
	
	for ( rdi = rd->rd_item; rdi != NULL; rdi = rdi->rdi_next ) {
		if ( op->o_abandon ) {
			return rs->sr_err = SLAPD_ABANDON;
		}

		rs->sr_err = test_filter( op, &rdi->rdi_e, op->ors_filter );
		if ( rs->sr_err == LDAP_COMPARE_TRUE ) {
			if ( op->ors_slimit == rs->sr_nentries ) {
				rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
				goto done;
			}

			/* safe default */
			rs->sr_attrs = op->ors_attrs;
			rs->sr_operational_attrs = NULL;
			rs->sr_ctrls = NULL;
			rs->sr_flags = 0;
			rs->sr_err = LDAP_SUCCESS;
			rs->sr_entry = &rdi->rdi_e;

			rs->sr_err = send_search_entry( op, rs );
			rs->sr_entry = NULL;

			switch ( rs->sr_err ) {
			case LDAP_UNAVAILABLE:	/* connection closed */
				rs->sr_err = LDAP_OTHER;
				/* fallthru */
			case LDAP_SIZELIMIT_EXCEEDED:
				goto done;
			}
		}
		rs->sr_err = LDAP_SUCCESS;
	}

done:;

	send_ldap_result( op, rs );

	return rs->sr_err;
}

static int
retcode_op_add( Operation *op, SlapReply *rs )
{
	return retcode_entry_response( op, rs, NULL, op->ora_e );
}

typedef struct retcode_cb_t {
	BackendInfo	*rdc_info;
	unsigned	rdc_flags;
	ber_tag_t	rdc_tag;
	AttributeName	*rdc_attrs;
} retcode_cb_t;

static int
retcode_cb_response( Operation *op, SlapReply *rs )
{
	retcode_cb_t	*rdc = (retcode_cb_t *)op->o_callback->sc_private;

	if ( rs->sr_type == REP_SEARCH ) {
		ber_tag_t	o_tag = op->o_tag;
		int		rc;

		op->o_tag = rdc->rdc_tag;
		if ( op->o_tag == LDAP_REQ_SEARCH ) {
			rs->sr_attrs = rdc->rdc_attrs;
		}
		rc = retcode_entry_response( op, rs, rdc->rdc_info, rs->sr_entry );
		op->o_tag = o_tag;

		return rc;
	}

	if ( rs->sr_err == LDAP_SUCCESS ) {
		if ( !op->o_abandon ) {
			rdc->rdc_flags = SLAP_CB_CONTINUE;
		}
		return 0;
	}

	return SLAP_CB_CONTINUE;
}

static int
retcode_op_internal( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;

	Operation	op2 = *op;
	BackendDB	db = *op->o_bd;
	slap_callback	sc = { 0 };
	retcode_cb_t	rdc;

	int		rc;

	op2.o_tag = LDAP_REQ_SEARCH;
	op2.ors_scope = LDAP_SCOPE_BASE;
	op2.ors_deref = LDAP_DEREF_NEVER;
	op2.ors_tlimit = SLAP_NO_LIMIT;
	op2.ors_slimit = SLAP_NO_LIMIT;
	op2.ors_limit = NULL;
	op2.ors_attrsonly = 0;
	op2.ors_attrs = slap_anlist_all_attributes;

	ber_str2bv_x( "(objectClass=errAbsObject)",
		STRLENOF( "(objectClass=errAbsObject)" ),
		1, &op2.ors_filterstr, op2.o_tmpmemctx );
	op2.ors_filter = str2filter_x( &op2, op2.ors_filterstr.bv_val );

	db.bd_info = on->on_info->oi_orig;
	op2.o_bd = &db;

	rdc.rdc_info = on->on_info->oi_orig;
	rdc.rdc_flags = RETCODE_FINDIR;
	if ( op->o_tag == LDAP_REQ_SEARCH ) {
		rdc.rdc_attrs = op->ors_attrs;
	}
	rdc.rdc_tag = op->o_tag;
	sc.sc_response = retcode_cb_response;
	sc.sc_private = &rdc;
	op2.o_callback = &sc;

	rc = op2.o_bd->be_search( &op2, rs );
	op->o_abandon = op2.o_abandon;

	filter_free_x( &op2, op2.ors_filter );
	ber_memfree_x( op2.ors_filterstr.bv_val, op2.o_tmpmemctx );

	if ( rdc.rdc_flags == SLAP_CB_CONTINUE ) {
		return SLAP_CB_CONTINUE;
	}

	return rc;
}

static int
retcode_op_func( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	retcode_item_t	*rdi;
	struct berval		nrdn, npdn;

	slap_callback		*cb = NULL;

	/* sleep as required */
	if ( rd->rd_sleep < 0 ) {
		sleep( rand() % ( - rd->rd_sleep ) );

	} else if ( rd->rd_sleep > 0 ) {
		sleep( rd->rd_sleep );
	}

	if ( !dnIsSuffix( &op->o_req_ndn, &rd->rd_npdn ) ) {
		if ( RETCODE_INDIR( rd ) ) {
			switch ( op->o_tag ) {
			case LDAP_REQ_ADD:
				return retcode_op_add( op, rs );

			case LDAP_REQ_BIND:
				/* skip if rootdn */
				if ( be_isroot_pw( op ) ) {
					return SLAP_CB_CONTINUE;
				}
				return retcode_op_internal( op, rs );

			case LDAP_REQ_SEARCH:
				if ( op->ors_scope == LDAP_SCOPE_BASE ) {
					rs->sr_err = retcode_op_internal( op, rs );
					switch ( rs->sr_err ) {
					case SLAP_CB_CONTINUE:
						if ( rs->sr_nentries == 0 ) {
							break;
						}
						rs->sr_err = LDAP_SUCCESS;
						/* fallthru */

					default:
						send_ldap_result( op, rs );
						break;
					}
					return rs->sr_err;
				}
				break;

			case LDAP_REQ_MODIFY:
			case LDAP_REQ_DELETE:
			case LDAP_REQ_MODRDN:
			case LDAP_REQ_COMPARE:
				return retcode_op_internal( op, rs );
			}
		}

		return SLAP_CB_CONTINUE;
	}

	if ( op->o_tag == LDAP_REQ_SEARCH
			&& op->ors_scope != LDAP_SCOPE_BASE
			&& op->o_req_ndn.bv_len == rd->rd_npdn.bv_len )
	{
		return retcode_send_onelevel( op, rs );
	}

	dnParent( &op->o_req_ndn, &npdn );
	if ( npdn.bv_len != rd->rd_npdn.bv_len ) {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		rs->sr_matched = rd->rd_pdn.bv_val;
		send_ldap_result( op, rs );
		rs->sr_matched = NULL;
		return rs->sr_err;
	}

	dnRdn( &op->o_req_ndn, &nrdn );

	for ( rdi = rd->rd_item; rdi != NULL; rdi = rdi->rdi_next ) {
		struct berval	rdi_nrdn;

		dnRdn( &rdi->rdi_ndn, &rdi_nrdn );
		if ( dn_match( &nrdn, &rdi_nrdn ) ) {
			break;
		}
	}

	if ( rdi != NULL && rdi->rdi_mask != SN_DG_OP_ALL ) {
		retcode_op_e	o_tag = SN_DG_OP_NONE;

		switch ( op->o_tag ) {
		case LDAP_REQ_ADD:
			o_tag = SN_DG_OP_ADD;
			break;

		case LDAP_REQ_BIND:
			o_tag = SN_DG_OP_BIND;
			break;

		case LDAP_REQ_COMPARE:
			o_tag = SN_DG_OP_COMPARE;
			break;

		case LDAP_REQ_DELETE:
			o_tag = SN_DG_OP_DELETE;
			break;

		case LDAP_REQ_MODIFY:
			o_tag = SN_DG_OP_MODIFY;
			break;

		case LDAP_REQ_MODRDN:
			o_tag = SN_DG_OP_RENAME;
			break;

		case LDAP_REQ_SEARCH:
			o_tag = SN_DG_OP_SEARCH;
			break;

		case LDAP_REQ_EXTENDED:
			o_tag = SN_DG_EXTENDED;
			break;

		default:
			/* Should not happen */
			break;
		}

		if ( !( o_tag & rdi->rdi_mask ) ) {
			return SLAP_CB_CONTINUE;
		}
	}

	if ( rdi == NULL ) {
		rs->sr_matched = rd->rd_pdn.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		rs->sr_text = "retcode not found";

	} else {
		rs->sr_err = rdi->rdi_err;
		rs->sr_text = rdi->rdi_text.bv_val;
		rs->sr_matched = rdi->rdi_matched.bv_val;

		/* FIXME: we only honor the rdi_ref field in case rdi_err
		 * is LDAP_REFERRAL otherwise send_ldap_result() bails out */
		if ( rs->sr_err == LDAP_REFERRAL ) {
			BerVarray	ref;

			if ( rdi->rdi_ref != NULL ) {
				ref = rdi->rdi_ref;
			} else {
				ref = default_referral;
			}

			if ( ref != NULL ) {
				rs->sr_ref = referral_rewrite( ref,
					NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );

			} else {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "bad referral object";
			}
		}

		if ( rdi->rdi_sleeptime > 0 ) {
			sleep( rdi->rdi_sleeptime );
		}
	}

	switch ( op->o_tag ) {
	case LDAP_REQ_EXTENDED:
		if ( rdi == NULL ) {
			break;
		}
		cb = ( slap_callback * )ch_malloc( sizeof( slap_callback ) );
		memset( cb, 0, sizeof( slap_callback ) );
		cb->sc_cleanup = retcode_cleanup_cb;
		op->o_callback = cb;
		break;

	default:
		send_ldap_result( op, rs );
		if ( rs->sr_ref != NULL ) {
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		}
		rs->sr_matched = NULL;
		rs->sr_text = NULL;
		break;
	}

	return rs->sr_err;
}

static int
retcode_op2str( ber_tag_t op, struct berval *bv )
{
	switch ( op ) {
	case LDAP_REQ_BIND:
		BER_BVSTR( bv, "bind" );
		return 0;
	case LDAP_REQ_ADD:
		BER_BVSTR( bv, "add" );
		return 0;
	case LDAP_REQ_DELETE:
		BER_BVSTR( bv, "delete" );
		return 0;
	case LDAP_REQ_MODRDN:
		BER_BVSTR( bv, "modrdn" );
		return 0;
	case LDAP_REQ_MODIFY:
		BER_BVSTR( bv, "modify" );
		return 0;
	case LDAP_REQ_COMPARE:
		BER_BVSTR( bv, "compare" );
		return 0;
	case LDAP_REQ_SEARCH:
		BER_BVSTR( bv, "search" );
		return 0;
	case LDAP_REQ_EXTENDED:
		BER_BVSTR( bv, "extended" );
		return 0;
	}
	return -1;
}

static int
retcode_entry_response( Operation *op, SlapReply *rs, BackendInfo *bi, Entry *e )
{
	Attribute	*a;
	int		err;
	char		*next;

	if ( get_manageDSAit( op ) ) {
		return SLAP_CB_CONTINUE;
	}

	if ( !is_entry_objectclass_or_sub( e, oc_errAbsObject ) ) {
		return SLAP_CB_CONTINUE;
	}

	/* operation */
	a = attr_find( e->e_attrs, ad_errOp );
	if ( a != NULL ) {
		int		i,
				gotit = 0;
		struct berval	bv = BER_BVNULL;

		(void)retcode_op2str( op->o_tag, &bv );

		if ( BER_BVISNULL( &bv ) ) {
			return SLAP_CB_CONTINUE;
		}

		for ( i = 0; !BER_BVISNULL( &a->a_nvals[ i ] ); i++ ) {
			if ( bvmatch( &a->a_nvals[ i ], &bv ) ) {
				gotit = 1;
				break;
			}
		}

		if ( !gotit ) {
			return SLAP_CB_CONTINUE;
		}
	}

	/* error code */
	a = attr_find( e->e_attrs, ad_errCode );
	if ( a == NULL ) {
		return SLAP_CB_CONTINUE;
	}
	err = strtol( a->a_nvals[ 0 ].bv_val, &next, 0 );
	if ( next == a->a_nvals[ 0 ].bv_val || next[ 0 ] != '\0' ) {
		return SLAP_CB_CONTINUE;
	}
	rs->sr_err = err;

	/* sleep time */
	a = attr_find( e->e_attrs, ad_errSleepTime );
	if ( a != NULL && a->a_nvals[ 0 ].bv_val[ 0 ] != '-' ) {
		int	sleepTime;

		sleepTime = strtoul( a->a_nvals[ 0 ].bv_val, &next, 0 );
		if ( next != a->a_nvals[ 0 ].bv_val && next[ 0 ] == '\0' ) {
			sleep( sleepTime );
		}
	}

	if ( rs->sr_err != LDAP_SUCCESS ) {
		BackendDB	db = *op->o_bd,
				*o_bd = op->o_bd;
		void		*o_callback = op->o_callback;

		/* message text */
		a = attr_find( e->e_attrs, ad_errText );
		if ( a != NULL ) {
			rs->sr_text = a->a_vals[ 0 ].bv_val;
		}

		/* matched DN */
		a = attr_find( e->e_attrs, ad_errMatchedDN );
		if ( a != NULL ) {
			rs->sr_matched = a->a_vals[ 0 ].bv_val;
		}

		if ( bi == NULL ) {
			slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;

			bi = on->on_info->oi_orig;
		}

		db.bd_info = bi;
		op->o_bd = &db;
		op->o_callback = NULL;

		/* referral */
		if ( rs->sr_err == LDAP_REFERRAL ) {
			BerVarray	refs = default_referral;

			a = attr_find( e->e_attrs, slap_schema.si_ad_ref );
			if ( a != NULL ) {
				refs = a->a_vals;
			}
			rs->sr_ref = referral_rewrite( refs,
				NULL, &op->o_req_dn, op->oq_search.rs_scope );
	
			send_search_reference( op, rs );
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;

		} else {
			send_ldap_result( op, rs );
		}

		rs->sr_text = NULL;
		rs->sr_matched = NULL;
		op->o_bd = o_bd;
		op->o_callback = o_callback;
	}
	
	if ( rs->sr_err != LDAP_SUCCESS ) {
		op->o_abandon = 1;
		return rs->sr_err;
	}

	return SLAP_CB_CONTINUE;
}

static int
retcode_response( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	if ( rs->sr_type != REP_SEARCH || !RETCODE_INDIR( rd ) ) {
		return SLAP_CB_CONTINUE;
	}

	return retcode_entry_response( op, rs, NULL, rs->sr_entry );
}

static int
retcode_db_init( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	retcode_t	*rd;

	rd = (retcode_t *)ch_malloc( sizeof( retcode_t ) );
	memset( rd, 0, sizeof( retcode_t ) );

	on->on_bi.bi_private = (void *)rd;

	return 0;
}

static int
retcode_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	char			*argv0 = argv[ 0 ] + STRLENOF( "retcode-" );

	if ( strncasecmp( argv[ 0 ], "retcode-", STRLENOF( "retcode-" ) ) != 0 ) {
		return SLAP_CONF_UNKNOWN;
	}

	if ( strcasecmp( argv0, "parent" ) == 0 ) {
		struct berval	dn;
		int		rc;

		if ( argc != 2 ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"\"retcode-parent <DN>\": missing <DN>\n",
				fname, lineno );
			return 1;
		}

		if ( !BER_BVISNULL( &rd->rd_pdn ) ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"parent already defined.\n", fname, lineno );
			return 1;
		}

		ber_str2bv( argv[ 1 ], 0, 0, &dn );

		rc = dnPrettyNormal( NULL, &dn, &rd->rd_pdn, &rd->rd_npdn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"unable to normalize parent DN \"%s\": %d\n",
				fname, lineno, argv[ 1 ], rc );
			return 1;
		}

	} else if ( strcasecmp( argv0, "item" ) == 0 ) {
		retcode_item_t	rdi = { BER_BVNULL }, **rdip;
		struct berval		bv, rdn, nrdn;
		int			rc;
		char			*next = NULL;

		if ( argc < 3 ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"\"retcode-item <RDN> <retcode> [<text>]\": "
				"missing args\n",
				fname, lineno );
			return 1;
		}

		ber_str2bv( argv[ 1 ], 0, 0, &bv );
		
		rc = dnPrettyNormal( NULL, &bv, &rdn, &nrdn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"unable to normalize RDN \"%s\": %d\n",
				fname, lineno, argv[ 1 ], rc );
			return 1;
		}

		if ( !dnIsOneLevelRDN( &nrdn ) ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"value \"%s\" is not a RDN\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

		if ( BER_BVISNULL( &rd->rd_npdn ) ) {
			/* FIXME: we use the database suffix */
			if ( be->be_nsuffix == NULL ) {
				fprintf( stderr, "%s: line %d: retcode: "
					"either \"retcode-parent\" "
					"or \"suffix\" must be defined.\n",
					fname, lineno );
				return 1;
			}

			ber_dupbv( &rd->rd_pdn, &be->be_suffix[ 0 ] );
			ber_dupbv( &rd->rd_npdn, &be->be_nsuffix[ 0 ] );
		}

		build_new_dn( &rdi.rdi_dn, &rd->rd_pdn, &rdn, NULL );
		build_new_dn( &rdi.rdi_ndn, &rd->rd_npdn, &nrdn, NULL );

		ch_free( rdn.bv_val );
		ch_free( nrdn.bv_val );

		rdi.rdi_err = strtol( argv[ 2 ], &next, 0 );
		if ( next == argv[ 2 ] || next[ 0 ] != '\0' ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"unable to parse return code \"%s\"\n",
				fname, lineno, argv[ 2 ] );
			return 1;
		}

		rdi.rdi_mask = SN_DG_OP_ALL;

		if ( argc > 3 ) {
			int	i;

			for ( i = 3; i < argc; i++ ) {
				if ( strncasecmp( argv[ i ], "op=", STRLENOF( "op=" ) ) == 0 )
				{
					char		**ops;
					int		j;

					ops = ldap_str2charray( &argv[ i ][ STRLENOF( "op=" ) ], "," );
					assert( ops != NULL );

					rdi.rdi_mask = SN_DG_OP_NONE;

					for ( j = 0; ops[ j ] != NULL; j++ ) {
						if ( strcasecmp( ops[ j ], "add" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_ADD;

						} else if ( strcasecmp( ops[ j ], "bind" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_BIND;

						} else if ( strcasecmp( ops[ j ], "compare" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_COMPARE;

						} else if ( strcasecmp( ops[ j ], "delete" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_DELETE;

						} else if ( strcasecmp( ops[ j ], "modify" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_MODIFY;

						} else if ( strcasecmp( ops[ j ], "rename" ) == 0
							|| strcasecmp( ops[ j ], "modrdn" ) == 0 )
						{
							rdi.rdi_mask |= SN_DG_OP_RENAME;

						} else if ( strcasecmp( ops[ j ], "search" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_SEARCH;

						} else if ( strcasecmp( ops[ j ], "extended" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_EXTENDED;

						} else if ( strcasecmp( ops[ j ], "auth" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_AUTH;

						} else if ( strcasecmp( ops[ j ], "read" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_READ;

						} else if ( strcasecmp( ops[ j ], "write" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_WRITE;

						} else if ( strcasecmp( ops[ j ], "all" ) == 0 ) {
							rdi.rdi_mask |= SN_DG_OP_ALL;

						} else {
							fprintf( stderr, "retcode: unknown op \"%s\"\n",
								ops[ j ] );
							return 1;
						}
					}

					ldap_charray_free( ops );

				} else if ( strncasecmp( argv[ i ], "text=", STRLENOF( "text=" ) ) == 0 )
				{
					if ( !BER_BVISNULL( &rdi.rdi_text ) ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"\"text\" already provided.\n",
							fname, lineno );
						return 1;
					}
					ber_str2bv( &argv[ i ][ STRLENOF( "text=" ) ], 0, 1, &rdi.rdi_text );

				} else if ( strncasecmp( argv[ i ], "matched=", STRLENOF( "matched=" ) ) == 0 )
				{
					struct berval	dn;

					if ( !BER_BVISNULL( &rdi.rdi_matched ) ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"\"matched\" already provided.\n",
							fname, lineno );
						return 1;
					}
					ber_str2bv( &argv[ i ][ STRLENOF( "matched=" ) ], 0, 0, &dn );
					if ( dnPretty( NULL, &dn, &rdi.rdi_matched, NULL ) != LDAP_SUCCESS ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"unable to prettify matched DN \"%s\".\n",
							fname, lineno, &argv[ i ][ STRLENOF( "matched=" ) ] );
						return 1;
					}

				} else if ( strncasecmp( argv[ i ], "ref=", STRLENOF( "ref=" ) ) == 0 )
				{
					char		**refs;
					int		j;

					if ( rdi.rdi_ref != NULL ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"\"ref\" already provided.\n",
							fname, lineno );
						return 1;
					}

					if ( rdi.rdi_err != LDAP_REFERRAL ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"providing \"ref\"\n"
							"\talong with a non-referral "
							"resultCode may cause slapd failures\n"
							"\trelated to internal checks.\n",
							fname, lineno );
					}

					refs = ldap_str2charray( &argv[ i ][ STRLENOF( "ref=" ) ], " " );
					assert( refs != NULL );

					for ( j = 0; refs[ j ] != NULL; j++ ) {
						struct berval	bv;

						ber_str2bv( refs[ j ], 0, 1, &bv );
						ber_bvarray_add( &rdi.rdi_ref, &bv );
					}

					ldap_charray_free( refs );

				} else if ( strncasecmp( argv[ i ], "sleeptime=", STRLENOF( "sleeptime=" ) ) == 0 )
				{
					char		*next;
					if ( rdi.rdi_sleeptime != 0 ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"\"sleeptime\" already provided.\n",
							fname, lineno );
						return 1;
					}

					rdi.rdi_sleeptime = strtol( &argv[ i ][ STRLENOF( "sleeptime=" ) ], &next, 10 );
					if ( next == argv[ i ] || next[ 0 ] != '\0' ) {
						fprintf( stderr, "%s: line %d: retcode: "
							"unable to parse \"sleeptime=%s\".\n",
							fname, lineno, &argv[ i ][ STRLENOF( "sleeptime=" ) ] );
						return 1;
					}

				} else {
					fprintf( stderr, "%s: line %d: retcode: "
						"unknown option \"%s\".\n",
							fname, lineno, argv[ i ] );
					return 1;
				}
			}
		}

		for ( rdip = &rd->rd_item; *rdip; rdip = &(*rdip)->rdi_next )
			/* go to last */ ;

		
		*rdip = ( retcode_item_t * )ch_malloc( sizeof( retcode_item_t ) );
		*(*rdip) = rdi;

	} else if ( strcasecmp( argv0, "indir" ) == 0 ) {
		rd->rd_flags |= RETCODE_FINDIR;

	} else if ( strcasecmp( argv0, "sleep" ) == 0 ) {
		switch ( argc ) {
		case 1:
			fprintf( stderr, "%s: line %d: retcode: "
				"\"retcode-sleep <time>\": missing <time>\n",
				fname, lineno );
			return 1;

		case 2:
			break;

		default:
			fprintf( stderr, "%s: line %d: retcode: "
				"\"retcode-sleep <time>\": extra cruft after <time>\n",
				fname, lineno );
			return 1;
		}

		if ( lutil_atoi( &rd->rd_sleep, argv[ 1 ] ) != 0 ) {
			fprintf( stderr, "%s: line %d: retcode: "
				"\"retcode-sleep <time>\": unable to parse <time>\n",
				fname, lineno );
			return 1;
		}

	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}

static int
retcode_db_open( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	retcode_item_t	*rdi;

	for ( rdi = rd->rd_item; rdi; rdi = rdi->rdi_next ) {
		LDAPRDN			rdn = NULL;
		int			rc, j;
		char*			p;
		struct berval		val[ 3 ];
		char			buf[ SLAP_TEXT_BUFLEN ];

		/* DN */
		rdi->rdi_e.e_name = rdi->rdi_dn;
		rdi->rdi_e.e_nname = rdi->rdi_ndn;

		/* objectClass */
		val[ 0 ] = oc_errObject->soc_cname;
		val[ 1 ] = slap_schema.si_oc_extensibleObject->soc_cname;
		BER_BVZERO( &val[ 2 ] );

		attr_merge( &rdi->rdi_e, slap_schema.si_ad_objectClass, val, NULL );

		/* RDN avas */
		rc = ldap_bv2rdn( &rdi->rdi_dn, &rdn, (char **) &p,
				LDAP_DN_FORMAT_LDAP );

		assert( rc == LDAP_SUCCESS );

		for ( j = 0; rdn[ j ]; j++ ) {
			LDAPAVA			*ava = rdn[ j ];
			AttributeDescription	*ad = NULL;
			const char		*text;

			rc = slap_bv2ad( &ava->la_attr, &ad, &text );
			assert( rc == LDAP_SUCCESS );
			
			attr_merge_normalize_one( &rdi->rdi_e, ad,
					&ava->la_value, NULL );
		}

		ldap_rdnfree( rdn );

		/* error code */
		snprintf( buf, sizeof( buf ), "%d", rdi->rdi_err );
		ber_str2bv( buf, 0, 0, &val[ 0 ] );

		attr_merge_one( &rdi->rdi_e, ad_errCode, &val[ 0 ], NULL );

		if ( rdi->rdi_ref != NULL ) {
			attr_merge_normalize( &rdi->rdi_e, slap_schema.si_ad_ref,
				rdi->rdi_ref, NULL );
		}

		/* text */
		if ( !BER_BVISNULL( &rdi->rdi_text ) ) {
			val[ 0 ] = rdi->rdi_text;

			attr_merge_normalize_one( &rdi->rdi_e, ad_errText, &val[ 0 ], NULL );
		}

		/* matched */
		if ( !BER_BVISNULL( &rdi->rdi_matched ) ) {
			val[ 0 ] = rdi->rdi_matched;

			attr_merge_normalize_one( &rdi->rdi_e, ad_errMatchedDN, &val[ 0 ], NULL );
		}

		/* sleep time */
		if ( rdi->rdi_sleeptime > 0 ) {
			snprintf( buf, sizeof( buf ), "%d", rdi->rdi_sleeptime );
			ber_str2bv( buf, 0, 0, &val[ 0 ] );

			attr_merge_one( &rdi->rdi_e, ad_errSleepTime, &val[ 0 ], NULL );
		}

		/* operations */
		if ( rdi->rdi_mask & SN_DG_OP_ADD ) {
			BER_BVSTR( &val[ 0 ], "add" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_BIND ) {
			BER_BVSTR( &val[ 0 ], "bind" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_COMPARE ) {
			BER_BVSTR( &val[ 0 ], "compare" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_DELETE ) {
			BER_BVSTR( &val[ 0 ], "delete" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_EXTENDED ) {
			BER_BVSTR( &val[ 0 ], "extended" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_MODIFY ) {
			BER_BVSTR( &val[ 0 ], "modify" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_RENAME ) {
			BER_BVSTR( &val[ 0 ], "rename" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}

		if ( rdi->rdi_mask & SN_DG_OP_SEARCH ) {
			BER_BVSTR( &val[ 0 ], "search" );
			attr_merge_normalize_one( &rdi->rdi_e, ad_errOp, &val[ 0 ], NULL );
		}
	}

	return 0;
}

static int
retcode_db_destroy( BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	retcode_t	*rd = (retcode_t *)on->on_bi.bi_private;

	if ( rd ) {
		retcode_item_t	*rdi, *next;

		for ( rdi = rd->rd_item; rdi != NULL; rdi = next ) {
			ber_memfree( rdi->rdi_dn.bv_val );
			ber_memfree( rdi->rdi_ndn.bv_val );

			if ( !BER_BVISNULL( &rdi->rdi_text ) ) {
				ber_memfree( rdi->rdi_text.bv_val );
			}

			if ( !BER_BVISNULL( &rdi->rdi_matched ) ) {
				ber_memfree( rdi->rdi_matched.bv_val );
			}

			if ( rdi->rdi_ref ) {
				ber_bvarray_free( rdi->rdi_ref );
			}

			BER_BVZERO( &rdi->rdi_e.e_name );
			BER_BVZERO( &rdi->rdi_e.e_nname );

			entry_clean( &rdi->rdi_e );

			next = rdi->rdi_next;

			ch_free( rdi );
		}

		if ( !BER_BVISNULL( &rd->rd_pdn ) ) {
			ber_memfree( rd->rd_pdn.bv_val );
		}

		if ( !BER_BVISNULL( &rd->rd_npdn ) ) {
			ber_memfree( rd->rd_npdn.bv_val );
		}

		ber_memfree( rd );
	}

	return 0;
}

#if SLAPD_OVER_RETCODE == SLAPD_MOD_DYNAMIC
static
#endif /* SLAPD_OVER_RETCODE == SLAPD_MOD_DYNAMIC */
int
retcode_initialize( void )
{
	int		i, code;
	const char	*err;

	static struct {
		char			*name;
		char			*desc;
		AttributeDescription	**ad;
	} retcode_at[] = {
	        { "errCode", "( 1.3.6.1.4.1.4203.666.11.4.1.1 "
		        "NAME ( 'errCode' ) "
		        "DESC 'LDAP error code' "
		        "EQUALITY integerMatch "
		        "ORDERING integerOrderingMatch "
		        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
			"SINGLE-VALUE )",
			&ad_errCode },
		{ "errOp", "( 1.3.6.1.4.1.4203.666.11.4.1.2 "
			"NAME ( 'errOp' ) "
			"DESC 'Operations the errObject applies to' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
			&ad_errOp},
		{ "errText", "( 1.3.6.1.4.1.4203.666.11.4.1.3 "
			"NAME ( 'errText' ) "
			"DESC 'LDAP error textual description' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"SINGLE-VALUE )",
			&ad_errText },
		{ "errSleepTime", "( 1.3.6.1.4.1.4203.666.11.4.1.4 "
			"NAME ( 'errSleepTime' ) "
			"DESC 'Time to wait before returning the error' "
			"EQUALITY integerMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
			"SINGLE-VALUE )",
			&ad_errSleepTime },
		{ "errMatchedDN", "( 1.3.6.1.4.1.4203.666.11.4.1.5 "
			"NAME ( 'errMatchedDN' ) "
			"DESC 'Value to be returned as matched DN' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE )",
			&ad_errMatchedDN },
		{ NULL }
	};

	static struct {
		char		*name;
		char		*desc;
		ObjectClass	**oc;
	} retcode_oc[] = {
		{ "errAbsObject", "( 1.3.6.1.4.1.4203.666.11.4.3.0 "
			"NAME ( 'errAbsObject' ) "
			"SUP top ABSTRACT "
			"MUST ( errCode ) "
			"MAY ( "
				"cn "
				"$ description "
				"$ errOp "
				"$ errText "
				"$ errSleepTime "
				"$ errMatchedDN "
			") )",
			&oc_errAbsObject },
		{ "errObject", "( 1.3.6.1.4.1.4203.666.11.4.3.1 "
			"NAME ( 'errObject' ) "
			"SUP errAbsObject STRUCTURAL "
			")",
			&oc_errObject },
		{ "errAuxObject", "( 1.3.6.1.4.1.4203.666.11.4.3.2 "
			"NAME ( 'errAuxObject' ) "
			"SUP errAbsObject AUXILIARY "
			")",
			&oc_errAuxObject },
		{ NULL }
	};


	for ( i = 0; retcode_at[ i ].name != NULL; i++ ) {
		LDAPAttributeType	*at;

		at = ldap_str2attributetype( retcode_at[ i ].desc,
			&code, &err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !at ) {
			fprintf( stderr, "retcode: "
				"AttributeType load failed: %s %s\n",
				ldap_scherr2str( code ), err );
			return code;
		}

#if LDAP_VENDOR_VERSION_MINOR == X || LDAP_VENDOR_VERSION_MINOR > 2
		code = at_add( at, 0, NULL, &err );
#else
		code = at_add( at, &err );
#endif
		ldap_memfree( at );
		if ( code != LDAP_SUCCESS ) {
			fprintf( stderr, "retcode: "
				"AttributeType load failed: %s %s\n",
				scherr2str( code ), err );
			return code;
		}

		code = slap_str2ad( retcode_at[ i ].name,
				retcode_at[ i ].ad, &err );
		if ( code != LDAP_SUCCESS ) {
			fprintf( stderr, "retcode: unable to find "
				"AttributeDescription \"%s\": %d (%s)\n",
				retcode_at[ i ].name, code, err );
			return 1;
		}
	}

	for ( i = 0; retcode_oc[ i ].name != NULL; i++ ) {
		LDAPObjectClass *oc;

		oc = ldap_str2objectclass( retcode_oc[ i ].desc,
				&code, &err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			fprintf( stderr, "retcode: "
				"ObjectClass load failed: %s %s\n",
				ldap_scherr2str( code ), err );
			return code;
		}

#if LDAP_VENDOR_VERSION_MINOR == X || LDAP_VENDOR_VERSION_MINOR > 2
		code = oc_add( oc, 0, NULL, &err );
#else
		code = oc_add( oc, &err );
#endif
		ldap_memfree(oc);
		if ( code != LDAP_SUCCESS ) {
			fprintf( stderr, "retcode: "
				"ObjectClass load failed: %s %s\n",
				scherr2str( code ), err );
			return code;
		}

		*retcode_oc[ i ].oc = oc_find( retcode_oc[ i ].name );
		if ( *retcode_oc[ i ].oc == NULL ) {
			fprintf( stderr, "retcode: unable to find "
				"objectClass \"%s\"\n",
				retcode_oc[ i ].name );
			return 1;
		}
	}

	retcode.on_bi.bi_type = "retcode";

	retcode.on_bi.bi_db_init = retcode_db_init;
	retcode.on_bi.bi_db_config = retcode_db_config;
	retcode.on_bi.bi_db_open = retcode_db_open;
	retcode.on_bi.bi_db_destroy = retcode_db_destroy;

	retcode.on_bi.bi_op_add = retcode_op_func;
	retcode.on_bi.bi_op_bind = retcode_op_func;
	retcode.on_bi.bi_op_compare = retcode_op_func;
	retcode.on_bi.bi_op_delete = retcode_op_func;
	retcode.on_bi.bi_op_modify = retcode_op_func;
	retcode.on_bi.bi_op_modrdn = retcode_op_func;
	retcode.on_bi.bi_op_search = retcode_op_func;

	retcode.on_bi.bi_extended = retcode_op_func;

	retcode.on_response = retcode_response;

	return overlay_register( &retcode );
}

#if SLAPD_OVER_RETCODE == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return retcode_initialize();
}
#endif /* SLAPD_OVER_RETCODE == SLAPD_MOD_DYNAMIC */

#endif /* SLAPD_OVER_RETCODE */

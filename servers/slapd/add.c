/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/socket.h>

#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"

static void init_add_pblock( Operation *op, struct berval *dn, Entry *e,
	int manageDSAit );
static int call_add_preop_plugins( Operation *op );
static void call_add_postop_plugins( Operation *op );
#endif /* LDAP_SLAPI */

int
do_add( Operation *op, SlapReply *rs )
{
	BerElement	*ber = op->o_ber;
	char		*last;
	struct berval	dn = BER_BVNULL;
	ber_len_t	len;
	ber_tag_t	tag;
	Entry		*e;
	Modifications	*modlist = NULL;
	Modifications	**modtail = &modlist;
	Modifications	tmp;

	Debug( LDAP_DEBUG_TRACE, "do_add\n", 0, 0, 0 );
	/*
	 * Parse the add request.  It looks like this:
	 *
	 *	AddRequest := [APPLICATION 14] SEQUENCE {
	 *		name	DistinguishedName,
	 *		attrs	SEQUENCE OF SEQUENCE {
	 *			type	AttributeType,
	 *			values	SET OF AttributeValue
	 *		}
	 *	}
	 */

	/* get the name */
	if ( ber_scanf( ber, "{m", /*}*/ &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn,
		op->o_tmpmemctx );

	if( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_add: invalid dn (%s)\n", dn.bv_val, 0, 0 );
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto done;
	}

	ber_dupbv( &e->e_name, &op->o_req_dn );
	ber_dupbv( &e->e_nname, &op->o_req_ndn );

	Debug( LDAP_DEBUG_ARGS, "do_add: dn (%s)\n", e->e_dn, 0, 0 );

	/* get the attrs */
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		Modifications *mod;
		ber_tag_t rtag;

		tmp.sml_nvalues = NULL;

		rtag = ber_scanf( ber, "{m{W}}", &tmp.sml_type, &tmp.sml_values );

		if ( rtag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "do_add: decoding error\n", 0, 0, 0 );
			send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
			rs->sr_err = SLAPD_DISCONNECT;
			goto done;
		}

		if ( tmp.sml_values == NULL ) {
			Debug( LDAP_DEBUG_ANY, "no values for type %s\n",
				tmp.sml_type.bv_val, 0, 0 );
			send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
				"no values for attribute type" );
			goto done;
		}

		mod  = (Modifications *) ch_malloc( sizeof(Modifications) );
		mod->sml_op = LDAP_MOD_ADD;
		mod->sml_next = NULL;
		mod->sml_desc = NULL;
		mod->sml_type = tmp.sml_type;
		mod->sml_values = tmp.sml_values;
		mod->sml_nvalues = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;
	}

	if ( ber_scanf( ber, /*{*/ "}") == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto done;
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_add: get_ctrls failed\n", 0, 0, 0 );
		goto done;
	} 

	if ( modlist == NULL ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
			"no attributes provided" );
		goto done;
	}

	Statslog( LDAP_DEBUG_STATS, "%s ADD dn=\"%s\"\n",
	    op->o_log_prefix, e->e_name.bv_val, 0, 0, 0 );

	if( e->e_nname.bv_len == 0 ) {
		/* protocolError may be a more appropriate error */
		send_ldap_error( op, rs, LDAP_ALREADY_EXISTS,
			"root DSE already exists" );
		goto done;

	} else if ( bvmatch( &e->e_nname, &frontendDB->be_schemandn ) ) {
		send_ldap_error( op, rs, LDAP_ALREADY_EXISTS,
			"subschema subentry already exists" );
		goto done;
	}

	/* temporary; remove if not invoking backend function */
	op->ora_e = e;
	op->ora_modlist = modlist;

	op->o_bd = frontendDB;
	rs->sr_err = frontendDB->be_add( op, rs );
	if ( rs->sr_err == 0 ) {
		e = NULL;
	}

done:;
	slap_graduate_commit_csn( op );

	if( modlist != NULL ) {
		slap_mods_free( modlist );
	}
	if( e != NULL ) {
		entry_free( e );
	}
	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );

	return rs->sr_err;
}

int
fe_op_add( Operation *op, SlapReply *rs )
{
	int		manageDSAit;
	Entry		*e = op->ora_e;
	Modifications	*modlist = op->ora_modlist;
	Modifications	**modtail = &modlist;

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	op->o_bd = select_backend( &e->e_nname, manageDSAit, 0 );
	if ( op->o_bd == NULL ) {
		rs->sr_ref = referral_rewrite( SLAPD_GLOBAL(default_referral),
			NULL, &e->e_name, LDAP_SCOPE_DEFAULT );
		if ( !rs->sr_ref ) rs->sr_ref = SLAPD_GLOBAL(default_referral);
		if ( rs->sr_ref ) {
			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			if ( rs->sr_ref != SLAPD_GLOBAL(default_referral) ) {
				ber_bvarray_free( rs->sr_ref );
			}
		} else {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"no global superior knowledge" );
		}
		goto done;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto done;
	}

	/* check for referrals */
	if( backend_check_referrals( op, rs ) != LDAP_SUCCESS ) {
		goto done;
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) init_add_pblock( op, &op->o_req_dn, e, manageDSAit );
#endif /* LDAP_SLAPI */

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the updatedn.
	 */
	if ( op->o_bd->be_add ) {
		/* do the update here */
		int repl_user = be_isupdate( op );
#ifndef SLAPD_MULTIMASTER
		if ( !SLAP_SHADOW(op->o_bd) || repl_user )
#endif
		{
			int update = op->o_bd->be_update_ndn.bv_len;
			char textbuf[SLAP_TEXT_BUFLEN];
			size_t textlen = sizeof textbuf;
			slap_callback cb = { NULL, slap_replog_cb, NULL, NULL };

			rs->sr_err = slap_mods_check( modlist, update, &rs->sr_text,
				  textbuf, textlen, NULL );

			if( rs->sr_err != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				goto done;
			}

			if ( !repl_user ) {
				for( modtail = &modlist;
					*modtail != NULL;
					modtail = &(*modtail)->sml_next )
				{
					assert( (*modtail)->sml_op == LDAP_MOD_ADD );
					assert( (*modtail)->sml_desc != NULL );
				}
				rs->sr_err = slap_mods_opattrs( op, modlist, modtail,
					&rs->sr_text, textbuf, textlen, 1 );
				if( rs->sr_err != LDAP_SUCCESS ) {
					send_ldap_result( op, rs );
					goto done;
				}
			}

			rs->sr_err = slap_mods2entry( modlist, &e, repl_user, 0,
				&rs->sr_text, textbuf, textlen );
			if( rs->sr_err != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				goto done;
			}

#ifdef LDAP_SLAPI
			/*
			 * Call the preoperation plugin here, because the entry
			 * will actually contain something.
			 */
			if ( op->o_pb ) {
				rs->sr_err = call_add_preop_plugins( op );
				if ( rs->sr_err != LDAP_SUCCESS ) {
					/* plugin will have sent result */
					goto done;
				}
			}
#endif /* LDAP_SLAPI */

			op->ora_e = e;
#ifdef SLAPD_MULTIMASTER
			if ( !repl_user )
#endif
			{
				cb.sc_next = op->o_callback;
				op->o_callback = &cb;
			}
			if ( (op->o_bd->be_add)( op, rs ) == 0 ) {
				be_entry_release_w( op, e );
				e = NULL;
			}

#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref = NULL;
#ifdef LDAP_SLAPI
			/*
			 * SLAPI_ADD_ENTRY will be empty, but this may be acceptable
			 * on replicas (for now, it involves the minimum code intrusion).
			 */
			if ( op->o_pb ) {
				rs->sr_err = call_add_preop_plugins( op );
				if ( rs->sr_err != LDAP_SUCCESS ) {
					/* plugin will have sent result */
					goto done;
				}
			}
#endif /* LDAP_SLAPI */

			defref = op->o_bd->be_update_refs
				? op->o_bd->be_update_refs : SLAPD_GLOBAL(default_referral);

			if ( defref != NULL ) {
				rs->sr_ref = referral_rewrite( defref,
					NULL, &e->e_name, LDAP_SCOPE_DEFAULT );
				if ( rs->sr_ref == NULL ) rs->sr_ref = defref;
				rs->sr_err = LDAP_REFERRAL;
				if (!rs->sr_ref) rs->sr_ref = SLAPD_GLOBAL(default_referral);
				send_ldap_result( op, rs );

				if ( rs->sr_ref != SLAPD_GLOBAL(default_referral) ) {
					ber_bvarray_free( rs->sr_ref );
				}
			} else {
				send_ldap_error( op, rs,
					LDAP_UNWILLING_TO_PERFORM,
					"shadow context; no update referral" );
			}
#endif /* SLAPD_MULTIMASTER */
		}
	} else {
#ifdef LDAP_SLAPI
		if ( op->o_pb ) {
			rs->sr_err = call_add_preop_plugins( op );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				/* plugin will have sent result */
				goto done;
			}
		}
#endif
	    Debug( LDAP_DEBUG_ARGS, "	 do_add: no backend support\n", 0, 0, 0 );
	    send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#ifdef LDAP_SLAPI
	if ( op->o_pb ) call_add_postop_plugins( op );
#endif /* LDAP_SLAPI */

done:;
	return rs->sr_err;
}

int
slap_mods2entry(
	Modifications *mods,
	Entry **e,
	int repl_user,
	int dup,
	const char **text,
	char *textbuf, size_t textlen )
{
	Attribute **tail = &(*e)->e_attrs;
	assert( *tail == NULL );

	*text = textbuf;

	for( ; mods != NULL; mods = mods->sml_next ) {
		Attribute *attr;

		if ( !repl_user ) {
			assert( mods->sml_op == LDAP_MOD_ADD );
		}
		assert( mods->sml_desc != NULL );

		attr = attr_find( (*e)->e_attrs, mods->sml_desc );

		if( attr != NULL ) {
#define SLURPD_FRIENDLY
#ifdef SLURPD_FRIENDLY
			ber_len_t i,j;

			if( !repl_user ) {
				snprintf( textbuf, textlen,
					"attribute '%s' provided more than once",
					mods->sml_desc->ad_cname.bv_val );
				return LDAP_TYPE_OR_VALUE_EXISTS;
			}

			for( i=0; attr->a_vals[i].bv_val; i++ ) {
				/* count them */
			}
			for( j=0; mods->sml_values[j].bv_val; j++ ) {
				/* count them */
			}
			j++;	/* NULL */
			
			attr->a_vals = ch_realloc( attr->a_vals,
				sizeof( struct berval ) * (i+j) );

			/* should check for duplicates */

			if ( dup ) {
				for ( j = 0; mods->sml_values[j].bv_val; j++ ) {
					ber_dupbv( &attr->a_vals[i+j], &mods->sml_values[j] );
				}
				BER_BVZERO( &attr->a_vals[i+j] );	
			} else {
				AC_MEMCPY( &attr->a_vals[i], mods->sml_values,
					sizeof( struct berval ) * j );
				ch_free( mods->sml_values );
				mods->sml_values = NULL;
			}

			if( mods->sml_nvalues ) {
				attr->a_nvals = ch_realloc( attr->a_nvals,
					sizeof( struct berval ) * (i+j) );
				if ( dup ) {
					for ( j = 0; mods->sml_nvalues[j].bv_val; j++ ) {
						ber_dupbv( &attr->a_nvals[i+j], &mods->sml_nvalues[j] );
					}
					BER_BVZERO( &attr->a_nvals[i+j] );	
				} else {
					AC_MEMCPY( &attr->a_nvals[i], mods->sml_nvalues,
						sizeof( struct berval ) * j );
					ch_free( mods->sml_nvalues );
					mods->sml_nvalues = NULL;
				}
			} else {
				attr->a_nvals = attr->a_vals;
			}

			continue;
#else
			snprintf( textbuf, textlen,
				"attribute '%s' provided more than once",
				mods->sml_desc->ad_cname.bv_val );
			return LDAP_TYPE_OR_VALUE_EXISTS;
#endif
		}

		if( mods->sml_values[1].bv_val != NULL ) {
			/* check for duplicates */
			int		i, j;
			MatchingRule *mr = mods->sml_desc->ad_type->sat_equality;

			/* check if the values we're adding already exist */
			if( mr == NULL || !mr->smr_match ) {
				for ( i = 1; mods->sml_values[i].bv_val != NULL; i++ ) {
					/* test asserted values against themselves */
					for( j = 0; j < i; j++ ) {
						if ( bvmatch( &mods->sml_values[i],
							&mods->sml_values[j] ) )
						{
							/* value exists already */
							snprintf( textbuf, textlen,
								"%s: value #%d provided more than once",
								mods->sml_desc->ad_cname.bv_val, j );
							return LDAP_TYPE_OR_VALUE_EXISTS;
						}
					}
				}

			} else {
				int	rc;
				int match;

				for ( i = 1; mods->sml_values[i].bv_val != NULL; i++ ) {
					/* test asserted values against themselves */
					for( j = 0; j < i; j++ ) {
						rc = value_match( &match, mods->sml_desc, mr,
							SLAP_MR_EQUALITY
							| SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX
							| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
							| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
							mods->sml_nvalues
								? &mods->sml_nvalues[i]
								: &mods->sml_values[i],
							mods->sml_nvalues
								? &mods->sml_nvalues[j]
								: &mods->sml_values[j],
							text );

						if ( rc == LDAP_SUCCESS && match == 0 ) {
							/* value exists already */
							snprintf( textbuf, textlen,
								"%s: value #%d provided more than once",
								mods->sml_desc->ad_cname.bv_val, j );
							return LDAP_TYPE_OR_VALUE_EXISTS;

						} else if ( rc != LDAP_SUCCESS ) {
							return rc;
						}
					}
				}
			}
		}

		attr = ch_calloc( 1, sizeof(Attribute) );

		/* move ad to attr structure */
		attr->a_desc = mods->sml_desc;
		if ( !dup ) mods->sml_desc = NULL;

		/* move values to attr structure */
		/*	should check for duplicates */
		if ( dup ) { 
			int i;
			for ( i = 0; mods->sml_values[i].bv_val; i++ ) /* EMPTY */;
			attr->a_vals = (BerVarray) ch_calloc( i+1, sizeof( BerValue ));
			for ( i = 0; mods->sml_values[i].bv_val; i++ ) {
				ber_dupbv( &attr->a_vals[i], &mods->sml_values[i] );
			}
			BER_BVZERO( &attr->a_vals[i] );
		} else {
			attr->a_vals = mods->sml_values;
			mods->sml_values = NULL;
		}

		if ( mods->sml_nvalues ) {
			if ( dup ) {
				int i;
				for ( i = 0; mods->sml_nvalues[i].bv_val; i++ ) /* EMPTY */;
				attr->a_nvals = (BerVarray) ch_calloc( i+1, sizeof( BerValue ));
				for ( i = 0; mods->sml_nvalues[i].bv_val; i++ ) {
					ber_dupbv( &attr->a_nvals[i], &mods->sml_nvalues[i] );
				}
				BER_BVZERO( &attr->a_nvals[i] );
			} else {
				attr->a_nvals = mods->sml_nvalues;
				mods->sml_nvalues = NULL;
			}
		} else {
			attr->a_nvals = attr->a_vals;
		}

		*tail = attr;
		tail = &attr->a_next;
	}

	return LDAP_SUCCESS;
}

int
slap_entry2mods(
	Entry *e,
	Modifications **mods,
	const char **text,
	char *textbuf, size_t textlen )
{
	Modifications	*modhead = NULL;
	Modifications	*mod;
	Modifications	**modtail = &modhead;
	Attribute		*a_new;
	AttributeDescription	*a_new_desc;
	int				i, count;

	a_new = e->e_attrs;

	while ( a_new != NULL ) {
		a_new_desc = a_new->a_desc;
		mod = (Modifications *) malloc( sizeof( Modifications ));
		
		mod->sml_op = LDAP_MOD_REPLACE;

		mod->sml_type = a_new_desc->ad_cname;

		for ( count = 0; a_new->a_vals[count].bv_val; count++ ) /* EMPTY */;

		mod->sml_values = (struct berval*) malloc(
			(count+1) * sizeof( struct berval) );

		/* see slap_mods_check() comments...
		 * if a_vals == a_nvals, there is no normalizer.
		 * in this case, mod->sml_nvalues must be left NULL.
		 */
		if ( a_new->a_vals != a_new->a_nvals ) {
			mod->sml_nvalues = (struct berval*) malloc(
				(count+1) * sizeof( struct berval) );
		} else {
			mod->sml_nvalues = NULL;
		}

		for ( i = 0; i < count; i++ ) {
			ber_dupbv(mod->sml_values+i, a_new->a_vals+i); 
			if ( mod->sml_nvalues ) {
				ber_dupbv( mod->sml_nvalues+i, a_new->a_nvals+i ); 
			} 
		}

		mod->sml_values[count].bv_val = NULL; 
		mod->sml_values[count].bv_len = 0; 

		if ( mod->sml_nvalues ) {
			mod->sml_nvalues[count].bv_val = NULL; 
			mod->sml_nvalues[count].bv_len = 0; 
		}

		mod->sml_desc = a_new_desc;
		mod->sml_next =NULL;
		*modtail = mod;
		modtail = &mod->sml_next;
		a_new = a_new->a_next; 
	}

	*mods = modhead;

	return LDAP_SUCCESS;
}

#ifdef LDAP_SLAPI
static void init_add_pblock( Operation *op,
	struct berval *dn, Entry *e, int manageDSAit )
{
	slapi_int_pblock_set_operation( op->o_pb, op );
	slapi_pblock_set( op->o_pb, SLAPI_ADD_TARGET, (void *)dn->bv_val );
	slapi_pblock_set( op->o_pb, SLAPI_ADD_ENTRY, (void *)e );
	slapi_pblock_set( op->o_pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );
}

static int call_add_preop_plugins( Operation *op )
{
	int rc;

	rc = slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_PRE_ADD_FN, op->o_pb );
	if ( rc < 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
		Debug(LDAP_DEBUG_TRACE,
			"do_add: add preoperation plugin failed.\n",
			0, 0, 0);

		if (( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,
			(void *)&rc ) != 0 ) || rc == LDAP_SUCCESS )
		{
			rc = LDAP_OTHER;
		}
	} else {
		rc = LDAP_SUCCESS;
	}

	return rc;
}

static void call_add_postop_plugins( Operation *op )
{
	int rc;

	rc = slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_POST_ADD_FN, op->o_pb );
	if ( rc < 0 ) {
		Debug(LDAP_DEBUG_TRACE,
			"do_add: add postoperation plugin failed\n",
			0, 0, 0);
	}
}
#endif /* LDAP_SLAPI */

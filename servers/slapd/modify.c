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

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif
#include "lutil.h"


int
do_modify(
    Operation	*op,
    SlapReply	*rs )
{
	struct berval dn = BER_BVNULL;
	char		*last;
	ber_tag_t	tag;
	ber_len_t	len;
	Modifications	*modlist = NULL;
	Modifications	**modtail = &modlist;
	int		increment = 0;

	Debug( LDAP_DEBUG_TRACE, "do_modify\n", 0, 0, 0 );

	/*
	 * Parse the modify request.  It looks like this:
	 *
	 *	ModifyRequest := [APPLICATION 6] SEQUENCE {
	 *		name	DistinguishedName,
	 *		mods	SEQUENCE OF SEQUENCE {
	 *			operation	ENUMERATED {
	 *				add	(0),
	 *				delete	(1),
	 *				replace	(2)
	 *			},
	 *			modification	SEQUENCE {
	 *				type	AttributeType,
	 *				values	SET OF AttributeValue
	 *			}
	 *		}
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{m" /*}*/, &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: ber_scanf failed\n", 0, 0, 0 );

		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn.bv_val, 0, 0 );

	/* collect modifications & save for later */
	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		ber_int_t mop;
		Modifications tmp, *mod;

		tmp.sml_nvalues = NULL;

		if ( ber_scanf( op->o_ber, "{i{m[W]}}", &mop,
		    &tmp.sml_type, &tmp.sml_values ) == LBER_ERROR )
		{
			send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR,
				"decoding modlist error" );
			rs->sr_err = SLAPD_DISCONNECT;
			goto cleanup;
		}

		mod = (Modifications *) ch_malloc( sizeof(Modifications) );
		mod->sml_op = mop;
		mod->sml_type = tmp.sml_type;
		mod->sml_values = tmp.sml_values;
		mod->sml_nvalues = NULL;
		mod->sml_desc = NULL;
		mod->sml_next = NULL;
		*modtail = mod;

		switch( mop ) {
		case LDAP_MOD_ADD:
			if ( mod->sml_values == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"do_modify: modify/add operation (%ld) requires values\n",
					(long) mop, 0, 0 );

				send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
					"modify/add operation requires values" );
				goto cleanup;
			}

			/* fall through */

		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE:
			break;

		case LDAP_MOD_INCREMENT:
			if( op->o_protocol >= LDAP_VERSION3 ) {
				increment++;
				if ( mod->sml_values == NULL ) {
					Debug( LDAP_DEBUG_ANY, "do_modify: "
						"modify/increment operation (%ld) requires value\n",
						(long) mop, 0, 0 );

					send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
						"modify/increment operation requires value" );
					goto cleanup;
				}

				if( mod->sml_values[1].bv_val ) {
					Debug( LDAP_DEBUG_ANY, "do_modify: modify/increment "
						"operation (%ld) requires single value\n",
						(long) mop, 0, 0 );

					send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
						"modify/increment operation requires single value" );
					goto cleanup;
				}

				break;
			}
			/* fall thru */

		default: {
				Debug( LDAP_DEBUG_ANY,
					"do_modify: unrecognized modify operation (%ld)\n",
					(long) mop, 0, 0 );

				send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
					"unrecognized modify operation" );
				goto cleanup;
			}
		}

		modtail = &mod->sml_next;
	}
	*modtail = NULL;

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: get_ctrls failed\n", 0, 0, 0 );

		goto cleanup;
	}

	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn,
		op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"do_modify: invalid dn (%s)\n", dn.bv_val, 0, 0 );
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto cleanup;
	}

	/* FIXME: temporary */
	op->orm_modlist = modlist;
	op->orm_increment = increment;

	op->o_bd = frontendDB;
	rs->sr_err = frontendDB->be_modify( op, rs );

cleanup:
	slap_graduate_commit_csn( op );

	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	if ( modlist != NULL ) slap_mods_free( modlist );

	return rs->sr_err;
}

int
fe_op_modify( Operation *op, SlapReply *rs )
{
#ifdef LDAP_DEBUG
	Modifications	*tmp;
#endif
	int		manageDSAit;
	Modifications	*modlist = op->orm_modlist;
	Modifications	**modtail = &modlist;
#ifdef LDAP_SLAPI
	LDAPMod		**modv = NULL;
#endif
	int		increment = op->orm_increment;
	
	if( op->o_req_ndn.bv_len == 0 ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: root dse!\n", 0, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"modify upon the root DSE not supported" );
		goto cleanup;

	} else if ( bvmatch( &op->o_req_ndn, &frontendDB->be_schemandn ) ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: subschema subentry!\n", 0, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"modification of subschema subentry not supported" );
		goto cleanup;
	}

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );

	for ( tmp = modlist; tmp != NULL; tmp = tmp->sml_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n",
			tmp->sml_op == LDAP_MOD_ADD ? "add" :
				(tmp->sml_op == LDAP_MOD_INCREMENT ? "increment" :
				(tmp->sml_op == LDAP_MOD_DELETE ? "delete" :
					"replace")), tmp->sml_type.bv_val, 0 );

		if ( tmp->sml_values == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tno values", NULL, NULL );
		} else if ( tmp->sml_values[0].bv_val == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tzero values", NULL, NULL );
		} else if ( tmp->sml_values[1].bv_val == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s, length %ld\n",
			   "\t\tone value", (long) tmp->sml_values[0].bv_len, NULL );
		} else {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tmultiple values", NULL, NULL );
		}
	}

	if ( StatslogTest( LDAP_DEBUG_STATS ) ) {
		char abuf[BUFSIZ/2], *ptr = abuf;
		int len = 0;

		Statslog( LDAP_DEBUG_STATS, "%s MOD dn=\"%s\"\n",
			op->o_log_prefix, op->o_req_dn.bv_val, 0, 0, 0 );

		for ( tmp = modlist; tmp != NULL; tmp = tmp->sml_next ) {
			if (len + 1 + tmp->sml_type.bv_len > sizeof(abuf)) {
				Statslog( LDAP_DEBUG_STATS, "%s MOD attr=%s\n",
				    op->o_log_prefix, abuf, 0, 0, 0 );

	    			len = 0;
				ptr = abuf;

				if( 1 + tmp->sml_type.bv_len > sizeof(abuf)) {
					Statslog( LDAP_DEBUG_STATS, "%s MOD attr=%s\n",
						op->o_log_prefix, tmp->sml_type.bv_val, 0, 0, 0 );
					continue;
				}
			}
			if (len) {
				*ptr++ = ' ';
				len++;
			}
			ptr = lutil_strcopy(ptr, tmp->sml_type.bv_val);
			len += tmp->sml_type.bv_len;
		}
		if (len) {
			Statslog( LDAP_DEBUG_STATS, "%s MOD attr=%s\n",
	    			op->o_log_prefix, abuf, 0, 0, 0 );
		}
	}
#endif	/* LDAP_DEBUG */

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	op->o_bd = select_backend( &op->o_req_ndn, manageDSAit, 0 );
	if ( op->o_bd == NULL ) {
		rs->sr_ref = referral_rewrite( default_referral,
			NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		if (!rs->sr_ref) rs->sr_ref = default_referral;

		if (rs->sr_ref != NULL ) {
			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			if (rs->sr_ref != default_referral) ber_bvarray_free( rs->sr_ref );
		} else {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"no global superior knowledge" );
		}
		goto cleanup;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

	/* check for referrals */
	if( backend_check_referrals( op, rs ) != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* check for modify/increment support */
	if( increment && !SLAP_INCREMENT( op->o_bd ) ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"modify/increment not supported in context" );
	}

#if defined( LDAP_SLAPI )
#define pb	op->o_pb
	if ( pb ) {
		slapi_int_pblock_set_operation( pb, op );
		slapi_pblock_set( pb, SLAPI_MODIFY_TARGET, (void *)op->o_req_dn.bv_val );
		slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );
		modv = slapi_int_modifications2ldapmods( &modlist );
		slapi_pblock_set( pb, SLAPI_MODIFY_MODS, (void *)modv );

		rs->sr_err = slapi_int_call_plugins( op->o_bd,
			SLAPI_PLUGIN_PRE_MODIFY_FN, pb );

		/*
		 * It's possible that the preoperation plugin changed the
		 * modification array, so we need to convert it back to
		 * a Modification list.
		 *
		 * Calling slapi_int_modifications2ldapmods() destroyed modlist so
		 * we don't need to free it.
		 */
		slapi_pblock_get( pb, SLAPI_MODIFY_MODS, (void **)&modv );
		modlist = slapi_int_ldapmods2modifications( modv );

		if ( rs->sr_err < 0 ) {
			/*
			 * A preoperation plugin failure will abort the
			 * entire operation.
			 */
			Debug(LDAP_DEBUG_TRACE,
				"do_modify: modify preoperation plugin failed.\n",
				0, 0, 0);
			if ( ( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,
				(void *)&rs->sr_err ) != 0 ) || rs->sr_err == LDAP_SUCCESS )
			{
				rs->sr_err = LDAP_OTHER;
			}
			slapi_int_free_ldapmods( modv );
			modv = NULL;
			goto cleanup;
		}
	}

	/*
	 * NB: it is valid for the plugin to return no modifications
	 * (for example, a plugin might store some attributes elsewhere
	 * and remove them from the modification list; if only those
	 * attribute types were included in the modification request,
	 * then slapi_int_ldapmods2modifications() above will return
	 * NULL).
	 *
	 * However, the post-operation plugin should still be 
	 * called.
	 */
#endif /* defined( LDAP_SLAPI ) */

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( op->o_bd->be_modify ) {
		/* do the update here */
		int repl_user = be_isupdate( op );

		/* Multimaster slapd does not have to check for replicator dn
		 * because it accepts each modify request
		 */
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
				goto cleanup;
			}

			if ( !repl_user ) {
				for( modtail = &modlist;
					*modtail != NULL;
					modtail = &(*modtail)->sml_next )
				{
					/* empty */
				}

				rs->sr_err = slap_mods_opattrs( op, modlist, modtail,
					&rs->sr_text, textbuf, textlen, 1 );
				if( rs->sr_err != LDAP_SUCCESS ) {
					send_ldap_result( op, rs );
					goto cleanup;
				}
			}

			op->orm_modlist = modlist;
#ifdef SLAPD_MULTIMASTER
			if ( !repl_user )
#endif
			{
				/* but we log only the ones not from a replicator user */
				cb.sc_next = op->o_callback;
				op->o_callback = &cb;
			}
			op->o_bd->be_modify( op, rs );

#ifndef SLAPD_MULTIMASTER
		/* send a referral */
		} else {
			BerVarray defref = op->o_bd->be_update_refs
				? op->o_bd->be_update_refs : default_referral;
			if ( defref != NULL ) {
				rs->sr_ref = referral_rewrite( defref,
					NULL, &op->o_req_dn,
					LDAP_SCOPE_DEFAULT );
				if (!rs->sr_ref) rs->sr_ref = defref;
				rs->sr_err = LDAP_REFERRAL;
				send_ldap_result( op, rs );
				if (rs->sr_ref != defref) {
					ber_bvarray_free( rs->sr_ref );
				}
			} else {
				send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
					"shadow context; no update referral" );
			}
#endif
		}
	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
		    "operation not supported within namingContext" );
	}

#if defined( LDAP_SLAPI )
	if ( pb != NULL && slapi_int_call_plugins( op->o_bd,
		SLAPI_PLUGIN_POST_MODIFY_FN, pb ) < 0 )
	{
		Debug(LDAP_DEBUG_TRACE,
			"do_modify: modify postoperation plugins failed.\n", 0, 0, 0);
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:;
#if defined( LDAP_SLAPI )
	if ( modv != NULL ) slapi_int_free_ldapmods( modv );
#endif

	return rs->sr_err;
}

/*
 * Do basic attribute type checking and syntax validation.
 */
int slap_mods_check(
	Modifications *ml,
	int update,
	const char **text,
	char *textbuf,
	size_t textlen,
	void *ctx )
{
	int rc;

	for( ; ml != NULL; ml = ml->sml_next ) {
		AttributeDescription *ad = NULL;

		/* convert to attribute description */
		rc = slap_bv2ad( &ml->sml_type, &ml->sml_desc, text );

		if( rc != LDAP_SUCCESS ) {
			snprintf( textbuf, textlen, "%s: %s",
				ml->sml_type.bv_val, *text );
			*text = textbuf;
			return rc;
		}

		ad = ml->sml_desc;

		if( slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& !slap_ad_is_binary( ad ))
		{
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
				"%s: requires ;binary transfer",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( !slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& slap_ad_is_binary( ad ))
		{
			/* attribute does not require binary transfer */
			snprintf( textbuf, textlen,
				"%s: disallows ;binary transfer",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( slap_ad_is_tag_range( ad )) {
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
				"%s: inappropriate use of tag range option",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if (!update && is_at_no_user_mod( ad->ad_type )) {
			/* user modification disallowed */
			snprintf( textbuf, textlen,
				"%s: no user modification allowed",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		if ( is_at_obsolete( ad->ad_type ) &&
			(( ml->sml_op != LDAP_MOD_REPLACE &&
				ml->sml_op != LDAP_MOD_DELETE ) ||
					ml->sml_values != NULL ))
		{
			/*
			 * attribute is obsolete,
			 * only allow replace/delete with no values
			 */
			snprintf( textbuf, textlen,
				"%s: attribute is obsolete",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		if ( ml->sml_op == LDAP_MOD_INCREMENT &&
#ifdef SLAPD_REAL_SYNTAX
			!is_at_syntax( ad->ad_type, SLAPD_REAL_SYNTAX ) &&
#endif
			!is_at_syntax( ad->ad_type, SLAPD_INTEGER_SYNTAX ) )
		{
			/*
			 * attribute values must be INTEGER or REAL
			 */
			snprintf( textbuf, textlen,
				"%s: attribute syntax inappropriate for increment",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		/*
		 * check values
		 */
		if( ml->sml_values != NULL ) {
			ber_len_t nvals;
			slap_syntax_validate_func *validate =
				ad->ad_type->sat_syntax->ssyn_validate;
			slap_syntax_transform_func *pretty =
				ad->ad_type->sat_syntax->ssyn_pretty;
 
			if( !pretty && !validate ) {
				*text = "no validator for syntax";
				snprintf( textbuf, textlen,
					"%s: no validator for syntax %s",
					ml->sml_type.bv_val,
					ad->ad_type->sat_syntax->ssyn_oid );
				*text = textbuf;
				return LDAP_INVALID_SYNTAX;
			}

			/*
			 * check that each value is valid per syntax
			 *	and pretty if appropriate
			 */
			for( nvals = 0; ml->sml_values[nvals].bv_val; nvals++ ) {
				struct berval pval;
				if( pretty ) {
					rc = pretty( ad->ad_type->sat_syntax,
						&ml->sml_values[nvals], &pval, ctx );
				} else {
					rc = validate( ad->ad_type->sat_syntax,
						&ml->sml_values[nvals] );
				}

				if( rc != 0 ) {
					snprintf( textbuf, textlen,
						"%s: value #%ld invalid per syntax",
						ml->sml_type.bv_val, (long) nvals );
					*text = textbuf;
					return LDAP_INVALID_SYNTAX;
				}

				if( pretty ) {
					ber_memfree_x( ml->sml_values[nvals].bv_val, ctx );
					ml->sml_values[nvals] = pval;
				}
			}

			/*
			 * a rough single value check... an additional check is needed
			 * to catch add of single value to existing single valued attribute
			 */
			if ((ml->sml_op == LDAP_MOD_ADD || ml->sml_op == LDAP_MOD_REPLACE)
				&& nvals > 1 && is_at_single_value( ad->ad_type ))
			{
				snprintf( textbuf, textlen,
					"%s: multiple values provided",
					ml->sml_type.bv_val );
				*text = textbuf;
				return LDAP_CONSTRAINT_VIOLATION;
			}

			/* if the type has a normalizer, generate the
			 * normalized values. otherwise leave them NULL.
			 *
			 * this is different from the rule for attributes
			 * in an entry - in an attribute list, the normalized
			 * value is set equal to the non-normalized value
			 * when there is no normalizer.
			 */
			if( nvals && ad->ad_type->sat_equality &&
				ad->ad_type->sat_equality->smr_normalize )
			{
				ml->sml_nvalues = ber_memalloc_x(
					(nvals+1)*sizeof(struct berval), ctx );

				for( nvals = 0; ml->sml_values[nvals].bv_val; nvals++ ) {
					rc = ad->ad_type->sat_equality->smr_normalize(
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						ad->ad_type->sat_syntax,
						ad->ad_type->sat_equality,
						&ml->sml_values[nvals], &ml->sml_nvalues[nvals], ctx );
					if( rc ) {
						Debug( LDAP_DEBUG_ANY,
							"<= str2entry NULL (ssyn_normalize %d)\n",
							rc, 0, 0 );
						snprintf( textbuf, textlen,
							"%s: value #%ld normalization failed",
							ml->sml_type.bv_val, (long) nvals );
						*text = textbuf;
						return rc;
					}
				}

				ml->sml_nvalues[nvals].bv_val = NULL;
				ml->sml_nvalues[nvals].bv_len = 0;
			}

			if( nvals ) {
				/* check for duplicates */
				int		i, j;
				MatchingRule *mr = ad->ad_type->sat_equality;

				/* check if the values we're adding already exist */
				if( mr == NULL || !mr->smr_match ) {
					for ( i = 1; ml->sml_values[i].bv_val != NULL; i++ ) {
						/* test asserted values against themselves */
						for( j = 0; j < i; j++ ) {
							if ( bvmatch( &ml->sml_values[i],
								&ml->sml_values[j] ) )
							{
								/* value exists already */
								snprintf( textbuf, textlen,
									"%s: value #%d provided more than once",
									ml->sml_desc->ad_cname.bv_val, j );
								*text = textbuf;
								return LDAP_TYPE_OR_VALUE_EXISTS;
							}
						}
					}

				} else {
					int rc;
					int match;

					for ( i = 1; ml->sml_values[i].bv_val != NULL; i++ ) {
						/* test asserted values against themselves */
						for( j = 0; j < i; j++ ) {
							rc = value_match( &match, ml->sml_desc, mr,
								SLAP_MR_EQUALITY
									| SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX
									| SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH
									| SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH,
								ml->sml_nvalues
									? &ml->sml_nvalues[i]
									: &ml->sml_values[i],
								ml->sml_nvalues
									? &ml->sml_nvalues[j]
									: &ml->sml_values[j],
								text );
							if ( rc == LDAP_SUCCESS && match == 0 ) {
								/* value exists already */
								snprintf( textbuf, textlen,
									"%s: value #%d provided more than once",
									ml->sml_desc->ad_cname.bv_val, j );
								*text = textbuf;
								return LDAP_TYPE_OR_VALUE_EXISTS;

							} else if ( rc != LDAP_SUCCESS ) {
								return rc;
							}
						}
					}
				}
			}

		}
	}

	return LDAP_SUCCESS;
}

int slap_mods_opattrs(
	Operation *op,
	Modifications *mods,
	Modifications **modtail,
	const char **text,
	char *textbuf, size_t textlen,
	int manage_ctxcsn )
{
	struct berval name, timestamp, csn;
	struct berval nname;
	char timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
	Modifications *mod;

	int mop = op->o_tag == LDAP_REQ_ADD
		? LDAP_MOD_ADD : LDAP_MOD_REPLACE;

	assert( modtail != NULL );
	assert( *modtail == NULL );

	if ( SLAP_LASTMOD( op->o_bd )) {
		struct tm *ltm;
#ifdef HAVE_GMTIME_R
		struct tm ltm_buf;
#endif
		time_t now = slap_get_time();

#ifdef HAVE_GMTIME_R
		ltm = gmtime_r( &now, &ltm_buf );
#else
		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
		ltm = gmtime( &now );
#endif /* HAVE_GMTIME_R */
		lutil_gentime( timebuf, sizeof(timebuf), ltm );

		slap_get_csn( op, csnbuf, sizeof(csnbuf), &csn, manage_ctxcsn );

#ifndef HAVE_GMTIME_R
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif

		timestamp.bv_val = timebuf;
		timestamp.bv_len = strlen(timebuf);

		if( op->o_dn.bv_len == 0 ) {
			BER_BVSTR( &name, SLAPD_ANONYMOUS );
			nname = name;
		} else {
			name = op->o_dn;
			nname = op->o_ndn;
		}
	}

	if( op->o_tag == LDAP_REQ_ADD ) {
		struct berval tmpval;

		if( global_schemacheck ) {
			int rc = mods_structural_class( mods, &tmpval,
				text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) return rc;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_structuralObjectClass;
			mod->sml_values =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &tmpval );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_nvalues[0], &tmpval );
			mod->sml_nvalues[1].bv_len = 0;
			mod->sml_nvalues[1].bv_val = NULL;
			assert( mod->sml_nvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;
		}

		if ( SLAP_LASTMOD( op->o_bd )) {
			char uuidbuf[ LDAP_LUTIL_UUIDSTR_BUFSIZE ];

			tmpval.bv_len = lutil_uuidstr( uuidbuf, sizeof( uuidbuf ) );
			tmpval.bv_val = uuidbuf;
		
			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_entryUUID;
			mod->sml_values =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &tmpval );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			(*mod->sml_desc->ad_type->sat_equality->smr_normalize)(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					mod->sml_desc->ad_type->sat_syntax,
					mod->sml_desc->ad_type->sat_equality,
					mod->sml_values, mod->sml_nvalues, NULL );
			mod->sml_nvalues[1].bv_len = 0;
			mod->sml_nvalues[1].bv_val = NULL;
			*modtail = mod;
			modtail = &mod->sml_next;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_creatorsName;
			mod->sml_values =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &name );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_nvalues[0], &nname );
			mod->sml_nvalues[1].bv_len = 0;
			mod->sml_nvalues[1].bv_val = NULL;
			assert( mod->sml_nvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_createTimestamp;
			mod->sml_values =
				(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_values[0], &timestamp );
			mod->sml_values[1].bv_len = 0;
			mod->sml_values[1].bv_val = NULL;
			assert( mod->sml_values[0].bv_val );
			mod->sml_nvalues = NULL;
			*modtail = mod;
			modtail = &mod->sml_next;
		}
	}

	if ( SLAP_LASTMOD( op->o_bd )) {
		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_entryCSN;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &csn );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues = NULL;
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifiersName;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &name );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues =
			(BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_nvalues[0], &nname );
		mod->sml_nvalues[1].bv_len = 0;
		mod->sml_nvalues[1].bv_val = NULL;
		assert( mod->sml_nvalues[0].bv_val );
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifyTimestamp;
		mod->sml_values = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_values[0], &timestamp );
		mod->sml_values[1].bv_len = 0;
		mod->sml_values[1].bv_val = NULL;
		assert( mod->sml_values[0].bv_val );
		mod->sml_nvalues = NULL;
		*modtail = mod;
		modtail = &mod->sml_next;
	}

	*modtail = NULL;
	return LDAP_SUCCESS;
}


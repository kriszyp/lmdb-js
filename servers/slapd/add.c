/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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

#include "ldap_pvt.h"
#include "slap.h"
#include "slapi.h"

#ifdef LDAP_SLAPI
static Slapi_PBlock *initAddPlugin( Backend *be, Connection *conn, Operation *op,
	struct berval *dn, Entry *e, int manageDSAit );
static int doPreAddPluginFNs( Backend *be, Slapi_PBlock *pb );
static void doPostAddPluginFNs( Backend *be, Slapi_PBlock *pb );
#endif /* LDAP_SLAPI */

int
do_add( Connection *conn, Operation *op )
{
	BerElement	*ber = op->o_ber;
	char		*last;
	struct berval dn = { 0, NULL };
	ber_len_t	len;
	ber_tag_t	tag;
	Entry		*e;
	Backend		*be;
	Modifications	*modlist = NULL;
	Modifications	**modtail = &modlist;
	Modifications	tmp;
	const char *text;
	int			rc = LDAP_SUCCESS;
	int	manageDSAit;
#ifdef LDAP_SLAPI
	Slapi_PBlock	*pb = NULL;
#endif /* LDAP_SLAPI */

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_add: conn %d enter\n", conn->c_connid,0,0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_add\n", 0, 0, 0 );
#endif
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
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_add: conn %d ber_scanf failed\n", conn->c_connid,0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	rc = dnPrettyNormal( NULL, &dn, &e->e_name, &e->e_nname );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_add: conn %d invalid dn (%s)\n", conn->c_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_add: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
			    "invalid DN", NULL, NULL );
		goto done;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"do_add: conn %d  dn (%s)\n", conn->c_connid, e->e_dn, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "do_add: dn (%s)\n", e->e_dn, 0, 0 );
#endif

	/* get the attrs */
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		Modifications *mod;
		ber_tag_t rtag;

		rtag = ber_scanf( ber, "{m{W}}", &tmp.sml_type, &tmp.sml_bvalues );

		if ( rtag == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				   "do_add: conn %d	 decoding error \n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_add: decoding error\n", 0, 0, 0 );
#endif
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = -1;
			goto done;
		}

		if ( tmp.sml_bvalues == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"do_add: conn %d	 no values for type %s\n",
				conn->c_connid, tmp.sml_type.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "no values for type %s\n",
				tmp.sml_type.bv_val, 0, 0 );
#endif
			send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
				NULL, "no values for attribute type", NULL, NULL );
			goto done;
		}
		mod  = (Modifications *) ch_malloc( sizeof(Modifications) );
		
		mod->sml_op = LDAP_MOD_ADD;
		mod->sml_next = NULL;
		mod->sml_desc = NULL;
		mod->sml_type = tmp.sml_type;
		mod->sml_bvalues = tmp.sml_bvalues;

		*modtail = mod;
		modtail = &mod->sml_next;
	}

	if ( ber_scanf( ber, /*{*/ "}") == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_add: conn %d ber_scanf failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto done;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_add: conn %d get_ctrls failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_add: get_ctrls failed\n", 0, 0, 0 );
#endif
		goto done;
	} 

	if ( modlist == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "no attributes provided", NULL, NULL );
		goto done;
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu ADD dn=\"%s\"\n",
	    op->o_connid, op->o_opid, e->e_dn, 0, 0 );

	if( e->e_nname.bv_len == 0 ) {
		/* protocolError may be a more appropriate error */
		send_ldap_result( conn, op, rc = LDAP_ALREADY_EXISTS,
			NULL, "root DSE already exists",
			NULL, NULL );
		goto done;

	} else if ( bvmatch( &e->e_nname, &global_schemandn ) ) {
		send_ldap_result( conn, op, rc = LDAP_ALREADY_EXISTS,
			NULL, "subschema subentry already exists",
			NULL, NULL );
		goto done;
	}

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	be = select_backend( &e->e_nname, manageDSAit, 0 );
	if ( be == NULL ) {
		BerVarray ref = referral_rewrite( default_referral,
			NULL, &e->e_name, LDAP_SCOPE_DEFAULT );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, ref ? ref : default_referral, NULL );

		if ( ref ) ber_bvarray_free( ref );
		goto done;
	}

	/* check restrictions */
	rc = backend_check_restrictions( be, conn, op, NULL, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto done;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, &e->e_name, &e->e_nname );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

#ifdef LDAP_SLAPI
	pb = initAddPlugin( be, conn, op, &dn, e, manageDSAit );
#endif /* LDAP_SLAPI */

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the updatedn.
	 */
	if ( be->be_add ) {
		/* do the update here */
		int repl_user = be_isupdate(be, &op->o_ndn );
#ifndef SLAPD_MULTIMASTER
		if ( !be->be_update_ndn.bv_len || repl_user )
#endif
		{
			int update = be->be_update_ndn.bv_len;
			char textbuf[SLAP_TEXT_BUFLEN];
			size_t textlen = sizeof textbuf;

			rc = slap_mods_check( modlist, update, &text,
				textbuf, textlen );

			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
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
				rc = slap_mods_opattrs( be, op, modlist, modtail, &text,
					textbuf, textlen );
				if( rc != LDAP_SUCCESS ) {
					send_ldap_result( conn, op, rc,
						NULL, text, NULL, NULL );
					goto done;
				}
			}

			rc = slap_mods2entry( modlist, &e, repl_user, &text,
				textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto done;
			}

#ifdef LDAP_SLAPI
			/*
			 * Call the preoperation plugin here, because the entry
			 * will actually contain something.
			 */
			rc = doPreAddPluginFNs( be, pb );
			if ( rc != LDAP_SUCCESS ) {
				/* plugin will have sent result */
				goto done;
			}
#endif /* LDAP_SLAPI */

			if ( (*be->be_add)( be, conn, op, e ) == 0 ) {
#ifdef SLAPD_MULTIMASTER
				if ( !repl_user )
#endif
				{
					replog( be, op, &e->e_name, &e->e_nname, e );
				}
				be_entry_release_w( be, conn, op, e );
				e = NULL;
			}

#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref;
			BerVarray ref;
#ifdef LDAP_SLAPI
			/*
			 * SLAPI_ADD_ENTRY will be empty, but this may be acceptable
			 * on replicas (for now, it involves the minimum code intrusion).
			 */
			rc = doPreAddPluginFNs( be, pb );
			if ( rc != LDAP_SUCCESS ) {
				/* plugin will have sent result */
				goto done;
			}
#endif /* LDAP_SLAPI */

			defref = be->be_update_refs
				? be->be_update_refs : default_referral;
			ref = referral_rewrite( defref,
				NULL, &e->e_name, LDAP_SCOPE_DEFAULT );

			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				ref ? ref : defref, NULL );

			if ( ref ) ber_bvarray_free( ref );
#endif /* SLAPD_MULTIMASTER */
		}
	} else {
#ifdef LDAP_SLAPI
	    rc = doPreAddPluginFNs( be, pb );
	    if ( rc != LDAP_SUCCESS ) {
		/* plugin will have sent result */
		goto done;
	    }
#endif
#ifdef NEW_LOGGING
	    LDAP_LOG( OPERATION, INFO, 
		       "do_add: conn %d	 no backend support\n", conn->c_connid, 0, 0 );
#else
	    Debug( LDAP_DEBUG_ARGS, "	 do_add: no backend support\n", 0, 0, 0 );
#endif
	    send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			      NULL, "operation not supported within namingContext", NULL, NULL );
	}

#ifdef LDAP_SLAPI
	doPostAddPluginFNs( be, pb );
#endif /* LDAP_SLAPI */

done:
	if( modlist != NULL ) {
		slap_mods_free( modlist );
	}
	if( e != NULL ) {
		entry_free( e );
	}

	return rc;
}

int
slap_mods2entry(
	Modifications *mods,
	Entry **e,
	int repl_user,
	const char **text,
	char *textbuf, size_t textlen )
{
	Attribute **tail = &(*e)->e_attrs;
	assert( *tail == NULL );

	*text = textbuf;

	for( ; mods != NULL; mods = mods->sml_next ) {
		Attribute *attr;

		assert( mods->sml_op == LDAP_MOD_ADD );
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
			for( j=0; mods->sml_bvalues[j].bv_val; j++ ) {
				/* count them */
			}
			j++;	/* NULL */
			
			attr->a_vals = ch_realloc( attr->a_vals,
				sizeof( struct berval ) * (i+j) );

			/* should check for duplicates */

			AC_MEMCPY( &attr->a_vals[i], mods->sml_bvalues,
				sizeof( struct berval ) * j );

			/* trim the mods array */
			ch_free( mods->sml_bvalues );
			mods->sml_bvalues = NULL;

			continue;
#else
			snprintf( textbuf, textlen,
				"attribute '%s' provided more than once",
				mods->sml_desc->ad_cname.bv_val );
			return LDAP_TYPE_OR_VALUE_EXISTS;
#endif
		}

		if( mods->sml_bvalues[1].bv_val != NULL ) {
			/* check for duplicates */
			int		i, j;
			MatchingRule *mr = mods->sml_desc->ad_type->sat_equality;

			/* check if the values we're adding already exist */
			if( mr == NULL || !mr->smr_match ) {
				for ( i = 0; mods->sml_bvalues[i].bv_val != NULL; i++ ) {
					/* test asserted values against themselves */
					for( j = 0; j < i; j++ ) {
						if ( bvmatch( &mods->sml_bvalues[i],
							&mods->sml_bvalues[j] ) ) {
							/* value exists already */
							snprintf( textbuf, textlen,
								"%s: value #%d provided more than once",
								mods->sml_desc->ad_cname.bv_val, j );
							return LDAP_TYPE_OR_VALUE_EXISTS;
						}
					}
				}

			} else {
				int		rc;
				const char	*text = NULL;
				char		textbuf[ SLAP_TEXT_BUFLEN ]  = { '\0' };
				
				rc = modify_check_duplicates( mods->sml_desc, mr,
						NULL, mods->sml_bvalues, 0,
						&text, textbuf, sizeof( textbuf ) );

				if ( rc != LDAP_SUCCESS ) {
					return rc;
				}
			}
		}

		attr = ch_calloc( 1, sizeof(Attribute) );

		/* move ad to attr structure */
		attr->a_desc = mods->sml_desc;
		mods->sml_desc = NULL;

		/* move values to attr structure */
		/*	should check for duplicates */
		attr->a_vals = mods->sml_bvalues;
		mods->sml_bvalues = NULL;

		*tail = attr;
		tail = &attr->a_next;
	}

	return LDAP_SUCCESS;
}

#ifdef LDAP_SLAPI
static Slapi_PBlock *initAddPlugin( Backend *be, Connection *conn, Operation *op,
	struct berval *dn, Entry *e, int manageDSAit )
{
	Slapi_PBlock *pb;

	pb = op->o_pb;

	slapi_x_backend_set_pb( pb, be );
	slapi_x_connection_set_pb( pb, conn );
	slapi_x_operation_set_pb( pb, op );

	slapi_pblock_set( pb, SLAPI_ADD_TARGET, (void *)dn->bv_val );
	slapi_pblock_set( pb, SLAPI_ADD_ENTRY, (void *)e );
	slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );

	return pb;
}

static int doPreAddPluginFNs( Backend *be, Slapi_PBlock *pb )
{
	int rc;

	rc = doPluginFNs( be, SLAPI_PLUGIN_PRE_ADD_FN, pb );
	if ( rc != 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_add: add preoperation plugin failed\n",
				0, 0, 0);
#else
		Debug(LDAP_DEBUG_TRACE, "do_add: add preoperation plugin failed.\n",
				0, 0, 0);
		if ( slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void *)&rc ) != 0 )
			rc = LDAP_OTHER;
#endif
	} else {
		rc = LDAP_SUCCESS;
	}

	return rc;
}

static void doPostAddPluginFNs( Backend *be, Slapi_PBlock *pb )
{
	int rc;

	rc = doPluginFNs( be, SLAPI_PLUGIN_POST_ADD_FN, pb );
	if ( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_add: add postoperation plugin failed\n",
				0, 0, 0);
#else
		Debug(LDAP_DEBUG_TRACE, "do_add: add preoperation plugin failed.\n",
				0, 0, 0);
#endif
	}
}
#endif /* LDAP_SLAPI */

/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

static int slap_mods2entry(
	Modifications *mods,
	Entry **e,
	const char **text );

int
do_add( Connection *conn, Operation *op )
{
	BerElement	*ber = op->o_ber;
	char		*dn, *ndn, *last;
	ber_len_t	len;
	ber_tag_t	tag;
	Entry		*e;
	Backend		*be;
	LDAPModList	*modlist = NULL;
	LDAPModList	**modtail = &modlist;
	Modifications *mods = NULL;
	const char *text;
	int			rc = LDAP_SUCCESS;

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
	if ( ber_scanf( ber, "{a", /*}*/ &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	ndn = ch_strdup( dn );

	if ( dn_normalize( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_add: invalid dn (%s)\n", dn, 0, 0 );
		send_ldap_result( conn, op, LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		free( dn );
		free( ndn );
		return LDAP_INVALID_DN_SYNTAX;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_dn = dn;
	e->e_ndn = ndn;
	e->e_attrs = NULL;
	e->e_private = NULL;

	Debug( LDAP_DEBUG_ARGS, "do_add: ndn (%s)\n", e->e_ndn, 0, 0 );

	/* get the attrs */
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		LDAPModList *mod = (LDAPModList *) ch_malloc( sizeof(LDAPModList) );
		mod->ml_op = LDAP_MOD_ADD;
		mod->ml_next = NULL;

		rc = ber_scanf( ber, "{a{V}}", &mod->ml_type, &mod->ml_bvalues );

		if ( rc == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "do_add: decoding error\n", 0, 0, 0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = -1;
			free( mod );
			goto done;
		}

		if ( mod->ml_bvalues == NULL ) {
			Debug( LDAP_DEBUG_ANY, "no values for type %s\n",
				mod->ml_type, 0, 0 );
			send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
				NULL, "no values for attribute type", NULL, NULL );
			free( mod->ml_type );
			free( mod );
			goto done;
		}

		*modtail = mod;
		modtail = &mod->ml_next;
	}

	if ( ber_scanf( ber, /*{*/ "}") == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_add: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto done;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_add: get_ctrls failed\n", 0, 0, 0 );
		goto done;
	} 

	if ( modlist == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "no attributes provided", NULL, NULL );
		goto done;
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d ADD dn=\"%s\"\n",
	    op->o_connid, op->o_opid, e->e_ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	be = select_backend( e->e_ndn );
	if ( be == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		goto done;
	}

	/* make sure this backend recongizes critical controls */
	rc = backend_check_controls( be, conn, op, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto done;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, e->e_dn, e->e_ndn );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if ( global_readonly || be->be_readonly ) {
		Debug( LDAP_DEBUG_ANY, "do_add: database is read-only\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "directory is read-only", NULL, NULL );
		goto done;
	}

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the updatedn.
	 */
	if ( be->be_add ) {
		/* do the update here */
#ifdef SLAPD_MULTIMASTER
		if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
			global_lastmod == ON)) && (be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn )) )
#else
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
#endif
		{
			int update = be->be_update_ndn != NULL;

			rc = slap_modlist2mods( modlist, update, &mods, &text );
			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto done;
			}

#ifndef SLAPD_MULTIMASTER
			if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
				global_lastmod == ON)) && !update )
#endif
			{
				Modifications **modstail;
				for( modstail = &mods;
					*modstail != NULL;
					modstail = &(*modstail)->sml_next )
				{
					assert( (*modstail)->sml_op == LDAP_MOD_ADD );
					assert( (*modstail)->sml_desc != NULL );
				}
				rc = slap_mods_opattrs( op, modstail, &text );
				if( rc != LDAP_SUCCESS ) {
					send_ldap_result( conn, op, rc,
						NULL, text, NULL, NULL );
					goto done;
				}
			}

			rc = slap_mods2entry( mods, &e, &text );
			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto done;
			}

			if ( (*be->be_add)( be, conn, op, e ) == 0 ) {
#ifdef SLAPD_MULTIMASTER
				if (be->be_update_ndn == NULL ||
					strcmp( be->be_update_ndn, op->o_ndn ))
#endif
				{
					replog( be, op, e->e_dn, e );
				}
				be_entry_release_w( be, e );
				e = NULL;
			}

#ifndef SLAPD_MULTIMASTER
		} else {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				be->be_update_refs ? be->be_update_refs : default_referral, NULL );
#endif
		}
	} else {
	    Debug( LDAP_DEBUG_ARGS, "    do_add: no backend support\n", 0, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

done:
	if( modlist != NULL ) {
		slap_modlist_free( modlist );
	}
	if( mods != NULL ) {
		slap_mods_free( mods );
	}
	if( e != NULL ) {
		entry_free( e );
	}

	return rc;
}

static int slap_mods2entry(
	Modifications *mods,
	Entry **e,
	const char **text )
{
	Attribute **tail = &(*e)->e_attrs;
	assert( *tail == NULL );

	for( ; mods != NULL; mods = mods->sml_next ) {
		Attribute *attr;

		assert( mods->sml_op == LDAP_MOD_ADD );
		assert( mods->sml_desc != NULL );

		attr = attr_find( (*e)->e_attrs, mods->sml_desc );

		if( attr != NULL ) {
#define SLURPD_FRIENDLY
#ifdef SLURPD_FRIENDLY
			ber_len_t i,j;

			for( i=0; attr->a_vals[i]; i++ ) {
				/* count them */
			}
			for( j=0; mods->sml_bvalues[j]; j++ ) {
				/* count them */
			}
			j++;	/* NULL */
			
			attr->a_vals = ch_realloc( attr->a_vals,
				sizeof( struct berval * ) * (i+j) );

			/* should check for duplicates */
			memcpy( &attr->a_vals[i], mods->sml_bvalues,
				sizeof( struct berval * ) * j );

			/* trim the mods array */
			ch_free( mods->sml_bvalues );
			mods->sml_bvalues = NULL;

			continue;
#else
			*text = "attribute provided more than once";
			return LDAP_TYPE_OR_VALUE_EXISTS;
#endif
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


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

#include "slap.h"

static void	add_created_attrs(Operation *op, Entry *e);

void
do_add( Connection *conn, Operation *op )
{
	BerElement	*ber = op->o_ber;
	char		*dn, *last;
	ber_len_t	len;
	ber_tag_t	tag;
	Entry		*e;
	Backend		*be;

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
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
		    "decoding error" );
		return;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_dn = dn;
	e->e_ndn = dn_normalize_case( ch_strdup( dn ) );
	e->e_private = NULL;

	dn = NULL;

	Debug( LDAP_DEBUG_ARGS, "    do_add: ndn (%s)\n", e->e_ndn, 0, 0 );

	/* get the attrs */
	e->e_attrs = NULL;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) ) {
		char		*type;
		struct berval	**vals;

		if ( ber_scanf( ber, "{a{V}}", &type, &vals ) == LBER_ERROR ) {
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			    NULL, "decoding error" );
			entry_free( e );
			return;
		}

		if ( vals == NULL ) {
			Debug( LDAP_DEBUG_ANY, "no values for type %s\n", type,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    NULL );
			free( type );
			entry_free( e );
			return;
		}

		attr_merge( e, type, vals );

		free( type );
		ber_bvecfree( vals );
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d ADD dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, e->e_ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	be = select_backend( e->e_ndn );
	if ( be == NULL ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the updatedn.
	 */
	if ( be->be_add ) {
		/* do the update here */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
		{
			if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
				global_lastmod == ON)) && be->be_update_ndn == NULL ) {

				add_created_attrs( op, e );
			}
			if ( (*be->be_add)( be, conn, op, e ) == 0 ) {
				replog( be, LDAP_REQ_ADD, e->e_dn, e, 0 );
				be_entry_release_w( be, e );
			}

		} else {
			entry_free( e );
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
			    default_referral );
		}
	} else {
	    Debug( LDAP_DEBUG_ARGS, "    do_add: HHH\n", 0, 0, 0 );
		entry_free( e );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}
}

static void
add_created_attrs( Operation *op, Entry *e )
{
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	Attribute	**a, **next;
	Attribute	*tmp;
	struct tm	*ltm;
	time_t		currenttime;

	Debug( LDAP_DEBUG_TRACE, "add_created_attrs\n", 0, 0, 0 );

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to add these attrs */
	for ( a = &e->e_attrs; *a != NULL; a = next ) {
		if ( strcasecmp( (*a)->a_type, "modifiersname" ) == 0 || 
			strcasecmp( (*a)->a_type, "modifytimestamp" ) == 0 ||
			strcasecmp( (*a)->a_type, "creatorsname" ) == 0 ||
			strcasecmp( (*a)->a_type, "createtimestamp" ) == 0 ) {
			tmp = *a;
			*a = (*a)->a_next;
			attr_free( tmp );
			next = a;
		} else {
			next = &(*a)->a_next;
		}
	}

	if ( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		bv.bv_val = "NULLDN";
		bv.bv_len = strlen( bv.bv_val );
	} else {
		bv.bv_val = op->o_dn;
		bv.bv_len = strlen( bv.bv_val );
	}
	attr_merge( e, "creatorsname", bvals );

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
	attr_merge( e, "createtimestamp", bvals );
}

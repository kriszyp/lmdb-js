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

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"

static void	modlist_free(LDAPModList *ml);
static void	add_lastmods(Operation *op, LDAPModList **ml);


void
do_modify(
    Connection	*conn,
    Operation	*op
)
{
	char		*ndn;
	char		*last;
	unsigned long	tag, len;
	LDAPModList	*modlist, *tmp;
	LDAPModList	**modtail;
	Backend		*be;

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

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &ndn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", ndn, 0, 0 );

	(void) dn_normalize_case( ndn );

	/* collect modifications & save for later */
	modlist = NULL;
	modtail = &modlist;

	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		(*modtail) = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );

		if ( ber_scanf( op->o_ber, "{i{a[V]}}", &(*modtail)->ml_op,
		    &(*modtail)->ml_type, &(*modtail)->ml_bvalues )
		    == LBER_ERROR )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "decoding error" );
			free( ndn );
			free( *modtail );
			*modtail = NULL;
			modlist_free( modlist );
			return;
		}

		if ( (*modtail)->ml_op != LDAP_MOD_ADD &&
		    (*modtail)->ml_op != LDAP_MOD_DELETE &&
		    (*modtail)->ml_op != LDAP_MOD_REPLACE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "unrecognized modify operation" );
			free( ndn );
			modlist_free( modlist );
			return;
		}

		if ( (*modtail)->ml_bvalues == NULL
			&& (*modtail)->ml_op != LDAP_MOD_DELETE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "no values given" );
			free( ndn );
			modlist_free( modlist );
			return;
		}
		attr_normalize( (*modtail)->ml_type );

		modtail = &(*modtail)->ml_next;
	}
	*modtail = NULL;

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
	for ( tmp = modlist; tmp != NULL; tmp = tmp->ml_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n",
			tmp->ml_op == LDAP_MOD_ADD
				? "add" : (tmp->ml_op == LDAP_MOD_DELETE
					? "delete" : "replace"), tmp->ml_type, 0 );
	}
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d MOD dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		modlist_free( modlist );
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	/* alias suffix if approp */
	ndn = suffixAlias ( ndn, op, be );

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modify ) {
		/* do the update here */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
		{
			if ( (be->be_lastmod == ON || ( be->be_lastmod == UNDEFINED &&
				global_lastmod == ON ) ) && be->be_update_ndn == NULL ) {
				add_lastmods( op, &modlist );
			}
			if ( (*be->be_modify)( be, conn, op, ndn, modlist ) == 0 ) {
				replog( be, LDAP_REQ_MODIFY, ndn, modlist, 0 );
			}

		/* send a referral */
		} else {
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
			    default_referral );
		}
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( ndn );
	modlist_free( modlist );
}

static void
modlist_free(
    LDAPModList	*ml
)
{
	LDAPModList *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->ml_next;

		free( ml->ml_type );
		if ( ml->ml_bvalues != NULL )
			ber_bvecfree( ml->ml_bvalues );

		free( ml );
	}
}

static void
add_lastmods( Operation *op, LDAPModList **modlist )
{
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	LDAPModList		**m;
	LDAPModList		*tmp;
	struct tm	*ltm;

	Debug( LDAP_DEBUG_TRACE, "add_lastmods\n", 0, 0, 0 );

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to modify these attrs */
	for ( m = modlist; *m != NULL; m = &(*m)->ml_next ) {
            if ( strcasecmp( (*m)->ml_type, "modifytimestamp" ) == 0 || 
				strcasecmp( (*m)->ml_type, "modifiersname" ) == 0 ||
				strcasecmp( (*m)->ml_type, "createtimestamp" ) == 0 || 
				strcasecmp( (*m)->ml_type, "creatorsname" ) == 0 ) {

                Debug( LDAP_DEBUG_TRACE,
					"add_lastmods: found lastmod attr: %s\n",
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
	tmp->ml_bvalues = (struct berval **) ch_calloc( 1,
	    2 * sizeof(struct berval *) );
	tmp->ml_bvalues[0] = ber_bvdup( &bv );
	tmp->ml_next = *modlist;
	*modlist = tmp;

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
	tmp = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );
	tmp->ml_type = ch_strdup( "modifytimestamp" );
	tmp->ml_op = LDAP_MOD_REPLACE;
	tmp->ml_bvalues = (struct berval **) ch_calloc( 1, 2 * sizeof(struct berval *) );
	tmp->ml_bvalues[0] = ber_bvdup( &bv );
	tmp->ml_next = *modlist;
	*modlist = tmp;
}

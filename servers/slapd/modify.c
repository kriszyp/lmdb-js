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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

extern Backend	*select_backend();

extern char		*default_referral;
extern time_t		currenttime;
extern pthread_mutex_t	currenttime_mutex;
extern int		global_lastmod;

static void	modlist_free();
static void	add_lastmods();

void
do_modify(
    Connection	*conn,
    Operation	*op
)
{
	char		*dn, *odn;
	char		*last;
	unsigned long	tag, len;
	LDAPMod		*mods, *tmp;
	LDAPMod		**modtail;
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

	if ( ber_scanf( op->o_ber, "{a", &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}
	odn = strdup( dn );
	dn_normalize( dn );

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn, 0, 0 );

	/* collect modifications & save for later */
	mods = NULL;
	modtail = &mods;
	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		(*modtail) = (LDAPMod *) ch_calloc( 1, sizeof(LDAPMod) );

		if ( ber_scanf( op->o_ber, "{i{a[V]}}", &(*modtail)->mod_op,
		    &(*modtail)->mod_type, &(*modtail)->mod_bvalues )
		    == LBER_ERROR )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "decoding error" );
			free( dn );
			free( odn );
			free( *modtail );
			modlist_free( mods );
			return;
		}

		if ( (*modtail)->mod_op != LDAP_MOD_ADD &&
		    (*modtail)->mod_op != LDAP_MOD_DELETE &&
		    (*modtail)->mod_op != LDAP_MOD_REPLACE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "unrecognized modify operation" );
			free( dn );
			free( odn );
			modlist_free( mods );
			return;
		}

		if ( (*modtail)->mod_bvalues == NULL && (*modtail)->mod_op
		  != LDAP_MOD_DELETE ) {
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "no values given" );
			free( dn );
			free( odn );
			modlist_free( mods );
			return;
		}
		attr_normalize( (*modtail)->mod_type );

		modtail = &(*modtail)->mod_next;
	}
	*modtail = NULL;

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
	for ( tmp = mods; tmp != NULL; tmp = tmp->mod_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n", tmp->mod_op
		    == LDAP_MOD_ADD ? "add" : (tmp->mod_op == LDAP_MOD_DELETE ?
		    "delete" : "replace"), tmp->mod_type, 0 );
	}
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d MOD dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, dn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( dn )) == NULL ) {
		free( dn );
		free( odn );
		modlist_free( mods );
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the updatedn.
	 */
	if ( be->be_modify != NULL ) {
		/* do the update here */
		if ( be->be_updatedn == NULL ||
			strcasecmp( be->be_updatedn, op->o_dn ) == 0 ) {

			if ( (be->be_lastmod == ON || ( be->be_lastmod == UNDEFINED &&
				global_lastmod == ON ) ) && be->be_updatedn == NULL ) {
				add_lastmods( op, &mods );
			}
			if ( (*be->be_modify)( be, conn, op, odn, mods ) == 0 ) {
				replog( be, LDAP_REQ_MODIFY, dn, mods, 0 );
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

	free( dn );
	free( odn );
	modlist_free( mods );
}

static void
modlist_free(
    LDAPMod	*mods
)
{
	LDAPMod	*next;

	for ( ; mods != NULL; mods = next ) {
		next = mods->mod_next;
		free( mods->mod_type );
		if ( mods->mod_bvalues != NULL )
			ber_bvecfree( mods->mod_bvalues );
		free( mods );
	}
}

static void
add_lastmods( Operation *op, LDAPMod **mods )
{
	char		buf[20];
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
	tmp->mod_type = strdup( "modifiersname" );
	tmp->mod_op = LDAP_MOD_REPLACE;
	tmp->mod_bvalues = (struct berval **) ch_calloc( 1,
	    2 * sizeof(struct berval *) );
	tmp->mod_bvalues[0] = ber_bvdup( &bv );
	tmp->mod_next = *mods;
	*mods = tmp;

	pthread_mutex_lock( &currenttime_mutex );
        ltm = localtime( &currenttime );
        strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
	pthread_mutex_unlock( &currenttime_mutex );
	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );
	tmp = (LDAPMod *) ch_calloc( 1, sizeof(LDAPMod) );
	tmp->mod_type = strdup( "modifytimestamp" );
	tmp->mod_op = LDAP_MOD_REPLACE;
	tmp->mod_bvalues = (struct berval **) ch_calloc( 1, 2 * sizeof(struct berval *) );
	tmp->mod_bvalues[0] = ber_bvdup( &bv );
	tmp->mod_next = *mods;
	*mods = tmp;
}

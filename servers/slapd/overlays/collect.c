/* collect.c - Demonstration of overlay code */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2008 The OpenLDAP Foundation.
 * Portions Copyright 2003 Howard Chu.
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
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_COLLECT

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"


/* This is a cheap hack to implement a collective attribute.
 *
 * This demonstration overlay looks for a specified attribute in an
 * ancestor of a given entry and adds that attribute to the given
 * entry when it is returned in a search response. It takes no effect
 * for any other operations. If the ancestor does not exist, there
 * is no effect. If no attribute was configured, there is no effect.
 */

typedef struct collect_info {
	struct collect_info *ci_next;
	struct berval ci_dn;
	AttributeDescription *ci_ad;
} collect_info;

static int
collect_response( Operation *op, SlapReply *rs )
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	collect_info *ci = on->on_bi.bi_private;

	/* If we've been configured and the current response is
	 * a search entry
	 */
	if ( ci && rs->sr_type == REP_SEARCH ) {
		Entry *new = NULL;
		int rc;

		op->o_bd->bd_info = (BackendInfo *)on->on_info;

		for (; ci; ci=ci->ci_next ) {
			BerVarray vals = NULL;

			/* Is our configured entry an ancestor of this one? */
			rc = rs->sr_entry->e_nname.bv_len - ci->ci_dn.bv_len;
			if ( rc < 1 || strcmp( rs->sr_entry->e_nname.bv_val + rc,
				ci->ci_dn.bv_val )) continue;

			/* Extract the values of the desired attribute from
			 * the ancestor entry
			 */
			rc = backend_attribute( op, NULL, &ci->ci_dn, ci->ci_ad, &vals, ACL_READ );

			/* If there are any values, merge them into the
			 * current entry
			 */
			if ( vals ) {
				/* The current entry may live in a cache, so
				 * don't modify it directly. Make a copy and
				 * work with that instead.
				 */
				if ( !new ) {
					new = entry_dup( rs->sr_entry );
				}
				attr_merge( new, ci->ci_ad, vals, NULL );
				ber_bvarray_free_x( vals, op->o_tmpmemctx );
			}
		}

		if ( new ) {
			rs->sr_entry = new;
			rs->sr_flags |= REP_ENTRY_MUSTBEFREED;
		}
	}
	/* Default is to just fall through to the normal processing */
	return SLAP_CB_CONTINUE;
}

static int collect_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	AttributeDescription *ad = NULL;

	/* The config syntax is "collectinfo <dn> <attribute-description>"
	 * and only one directive may be specified per overlay instance.
	 */

	if ( strcasecmp( argv[0], "collectinfo" ) == 0 ) {
		collect_info *ci;
		struct berval bv, dn;
		const char *text;
		if ( argc != 3 ) {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: argument missing in \"collectinfo <dn> <attribute-description>\" line.\n",
			fname, lineno, 0 );
		    	return( 1 );
		}
		ber_str2bv( argv[1], 0, 0, &bv );
		if ( dnNormalize( 0, NULL, NULL, &bv, &dn, NULL ) ) {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: invalid DN in \"collectinfo\" line: %s.\n",
			fname, lineno, text );
			return( 1 );
		}
		if ( slap_str2ad( argv[2], &ad, &text ) ) {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: attribute description unknown in \"collectinfo\" line: %s.\n",
			fname, lineno, text );
			return( 1 );
		}

		/* The on->on_bi.bi_private pointer can be used for
		 * anything this instance of the overlay needs.
		 */
		ci = ch_malloc( sizeof( collect_info ));
		ci->ci_ad = ad;
		ci->ci_dn = dn;
		ci->ci_next = on->on_bi.bi_private;
		on->on_bi.bi_private = ci;
		return 0;
	}
	return SLAP_CONF_UNKNOWN;
}

static slap_overinst collect;

int collect_initialize() {
	collect.on_bi.bi_type = "collect";
	collect.on_bi.bi_db_config = collect_config;
	collect.on_response = collect_response;

	return overlay_register( &collect );
}

#if SLAPD_OVER_COLLECT == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return collect_initialize();
}
#endif

#endif /* SLAPD_OVER_COLLECT */

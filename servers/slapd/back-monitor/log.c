/* log.c - deal with log subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
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

#include "slap.h"
#include <lber_pvt.h>
#include "lutil.h"
#include "ldif.h"
#include "back-monitor.h"

/*
 * log mutex
 */
ldap_pvt_thread_mutex_t		monitor_log_mutex;

static struct {
	int i;
	struct berval s;
	struct berval n;
} int_2_level[] = {
	{ LDAP_DEBUG_TRACE,	BER_BVC("Trace"),	BER_BVNULL },
	{ LDAP_DEBUG_PACKETS,	BER_BVC("Packets"),	BER_BVNULL },
	{ LDAP_DEBUG_ARGS,	BER_BVC("Args"),	BER_BVNULL },
	{ LDAP_DEBUG_CONNS,	BER_BVC("Conns"),	BER_BVNULL },
	{ LDAP_DEBUG_BER,	BER_BVC("BER"),	BER_BVNULL },
	{ LDAP_DEBUG_FILTER,	BER_BVC("Filter"),	BER_BVNULL },
	{ LDAP_DEBUG_CONFIG,	BER_BVC("Config"),	BER_BVNULL },	/* useless */
	{ LDAP_DEBUG_ACL,	BER_BVC("ACL"),	BER_BVNULL },
	{ LDAP_DEBUG_STATS,	BER_BVC("Stats"),	BER_BVNULL },
	{ LDAP_DEBUG_STATS2,	BER_BVC("Stats2"),	BER_BVNULL },
	{ LDAP_DEBUG_SHELL,	BER_BVC("Shell"),	BER_BVNULL },
	{ LDAP_DEBUG_PARSE,	BER_BVC("Parse"),	BER_BVNULL },
	{ LDAP_DEBUG_CACHE,	BER_BVC("Cache"),	BER_BVNULL },
	{ LDAP_DEBUG_INDEX,	BER_BVC("Index"),	BER_BVNULL },
	{ 0,			BER_BVNULL,	BER_BVNULL }
};

static int loglevel2int( struct berval *l );
static int int2loglevel( int n );

static int add_values( Entry *e, Modification *mod, int *newlevel );
static int delete_values( Entry *e, Modification *mod, int *newlevel );
static int replace_values( Entry *e, Modification *mod, int *newlevel );

/*
 * initializes log subentry
 */
int
monitor_subsys_log_init(
	BackendDB	*be,
	monitorsubsys	*ms
)
{
	struct monitorinfo	*mi;
	Entry			*e;
	int			i;
	struct berval		desc[] = {
		BER_BVC("This entry allows to set the log level runtime."),
		BER_BVC("Set the attribute 'managedInfo' to the desired log levels."),
		BER_BVNULL
	};

	ldap_pvt_thread_mutex_init( &monitor_log_mutex );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, &ms->mss_ndn, 
				&e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_log_init: "
			"unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	/* initialize the debug level(s) */
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( mi->mi_ad_managedInfo->ad_type->sat_equality->smr_normalize ) {
			int	rc;

			rc = (*mi->mi_ad_managedInfo->ad_type->sat_equality->smr_normalize)(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					mi->mi_ad_managedInfo->ad_type->sat_syntax,
					mi->mi_ad_managedInfo->ad_type->sat_equality,
					&int_2_level[ i ].s,
					&int_2_level[ i ].n, NULL );
			if ( rc ) {
				return( -1 );
			}
		}

		if ( int_2_level[ i ].i & ldap_syslog ) {
			attr_merge_one( e, mi->mi_ad_managedInfo,
					&int_2_level[ i ].s,
					&int_2_level[ i ].n );
		}
	}

	attr_merge( e, mi->mi_ad_description, desc, NULL );

	monitor_cache_release( mi, e );

	return( 0 );
}

int 
monitor_subsys_log_modify( 
	Operation		*op,
	Entry 			*e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	int		rc = LDAP_OTHER;
	int		newlevel = ldap_syslog;
	Attribute	*save_attrs;
	Modifications	*modlist = op->oq_modify.rs_modlist;
	Modifications	*ml;

	ldap_pvt_thread_mutex_lock( &monitor_log_mutex );

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		Modification	*mod = &ml->sml_mod;

		/*
		 * accept all operational attributes
		 */
		if ( is_at_operational( mod->sm_desc->ad_type ) ) {
			( void ) attr_delete( &e->e_attrs, mod->sm_desc );
			rc = attr_merge( e, mod->sm_desc, mod->sm_values, mod->sm_nvalues );
			if ( rc != 0 ) {
				rc = LDAP_OTHER;
				break;
			}
			continue;

		/*
		 * only the monitor description attribute can be modified
		 */
		} else if ( mod->sm_desc != mi->mi_ad_managedInfo) {
			rc = LDAP_UNWILLING_TO_PERFORM;
			break;
		}

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			rc = add_values( e, mod, &newlevel );
			break;
			
		case LDAP_MOD_DELETE:
			rc = delete_values( e, mod, &newlevel );
			break;

		case LDAP_MOD_REPLACE:
			rc = replace_values( e, mod, &newlevel );
			break;

		default:
			rc = LDAP_OTHER;
			break;
		}

		if ( rc != LDAP_SUCCESS ) {
			break;
		}
	}

	/* set the new debug level */
	if ( rc == LDAP_SUCCESS ) {
		const char	*text;
		static char	textbuf[ BACKMONITOR_BUFSIZE ];

		/* check for abandon */
		if ( op->o_abandon ) {
			rc = SLAPD_ABANDON;

			goto cleanup;
		}

		/* check that the entry still obeys the schema */
		rc = entry_schema_check( be_monitor, e, save_attrs, 
				&text, textbuf, sizeof( textbuf ) );
		if ( rc != LDAP_SUCCESS ) {
			goto cleanup;
		}

		/*
		 * Do we need to protect this with a mutex?
		 */
		ldap_syslog = newlevel;

#if 0	/* debug rather than log */
		slap_debug = newlevel;
		lutil_set_debug_level( "slapd", slap_debug );
		ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &slap_debug);
		ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &slap_debug);
		ldif_debug = slap_debug;
#endif
	}

cleanup:;
	if ( rc == LDAP_SUCCESS ) {
		attrs_free( save_attrs );

	} else {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
	}
	
	ldap_pvt_thread_mutex_unlock( &monitor_log_mutex );

	return( rc );
}

static int
loglevel2int( struct berval *l )
{
	int		i;
	
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( l->bv_len != int_2_level[ i ].s.bv_len ) {
			continue;
		}

		if ( strcasecmp( l->bv_val, int_2_level[ i ].s.bv_val ) == 0 ) {
			return int_2_level[ i ].i;
		}
	}

	return 0;
}

static int
int2loglevel( int n )
{
	int		i;
	
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( int_2_level[ i ].i == n ) {
			return i;
		}
	}

	return -1;
}

static int
check_constraints( Modification *mod, int *newlevel )
{
	int		i;

	for ( i = 0; mod->sm_values && !BER_BVISNULL( &mod->sm_values[ i ] ); i++ ) {
		int		l;
		
		l = loglevel2int( &mod->sm_values[ i ] );
		if ( !l ) {
			return LDAP_CONSTRAINT_VIOLATION;
		}

		if ( ( l = int2loglevel( l ) ) == -1 ) {
			return LDAP_OTHER;
		}

		assert( int_2_level[ l ].s.bv_len
				== mod->sm_values[ i ].bv_len );
		
		AC_MEMCPY( mod->sm_values[ i ].bv_val,
				int_2_level[ l ].s.bv_val,
				int_2_level[ l ].s.bv_len );

		AC_MEMCPY( mod->sm_nvalues[ i ].bv_val,
				int_2_level[ l ].n.bv_val,
				int_2_level[ l ].n.bv_len );

		*newlevel |= l;
	}

	return LDAP_SUCCESS;
}	

static int 
add_values( Entry *e, Modification *mod, int *newlevel )
{
	Attribute	*a;
	int		i, rc;
	MatchingRule 	*mr = mod->sm_desc->ad_type->sat_equality;

	rc = check_constraints( mod, newlevel );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	a = attr_find( e->e_attrs, mod->sm_desc );

	if ( a != NULL ) {
		/* "description" SHOULD have appropriate rules ... */
		if ( mr == NULL || !mr->smr_match ) {
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		for ( i = 0; !BER_BVISNULL( &mod->sm_values[ i ] ); i++ ) {
			int rc;
			int j;
			const char *text = NULL;
			struct berval asserted;

			rc = asserted_value_validate_normalize(
				mod->sm_desc, mr, SLAP_MR_EQUALITY,
				&mod->sm_values[ i ], &asserted, &text, NULL );

			if ( rc != LDAP_SUCCESS ) {
				return rc;
			}

			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ ) {
				int match;
				int rc = value_match( &match, mod->sm_desc, mr,
					0, &a->a_vals[ j ], &asserted, &text );

				if ( rc == LDAP_SUCCESS && match == 0 ) {
					free( asserted.bv_val );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}

			free( asserted.bv_val );
		}
	}

	/* no - add them */
	rc = attr_merge( e, mod->sm_desc, mod->sm_values, mod->sm_nvalues );
	if ( rc != LDAP_SUCCESS ) {
		/* this should return result of attr_mergeit */
		return rc;
	}

	return LDAP_SUCCESS;
}

static int
delete_values( Entry *e, Modification *mod, int *newlevel )
{
	int             i, j, k, found, rc, nl = 0;
	Attribute       *a;
	MatchingRule 	*mr = mod->sm_desc->ad_type->sat_equality;

	rc = check_constraints( mod, &nl );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	*newlevel &= ~nl;

	/* delete the entire attribute */
	if ( mod->sm_values == NULL ) {
		int rc = attr_delete( &e->e_attrs, mod->sm_desc );

		if ( rc ) {
			rc = LDAP_NO_SUCH_ATTRIBUTE;
		} else {
			*newlevel = 0;
			rc = LDAP_SUCCESS;
		}
		return rc;
	}

	if ( mr == NULL || !mr->smr_match ) {
		/* disallow specific attributes from being deleted if
		 * no equality rule */
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->sm_desc )) == NULL ) {
		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	/* find each value to delete */
	for ( i = 0; !BER_BVISNULL( &mod->sm_values[ i ] ); i++ ) {
		int rc;
		const char *text = NULL;

		struct berval asserted;

		rc = asserted_value_validate_normalize(
				mod->sm_desc, mr, SLAP_MR_EQUALITY,
				&mod->sm_values[ i ], &asserted, &text, NULL );

		if( rc != LDAP_SUCCESS ) return rc;

		found = 0;
		for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ ) {
			int match;
			int rc = value_match( &match, mod->sm_desc, mr,
				0,
				&a->a_vals[ j ], &asserted, &text );

			if( rc == LDAP_SUCCESS && match != 0 ) {
				continue;
			}

			/* found a matching value */
			found = 1;

			/* delete it */
			free( a->a_vals[ j ].bv_val );
			for ( k = j + 1; !BER_BVISNULL( &a->a_vals[ k ] ); k++ ) {
				a->a_vals[ k - 1 ] = a->a_vals[ k ];
			}
			BER_BVZERO( &a->a_vals[ k - 1 ] );

			break;
		}

		free( asserted.bv_val );

		/* looked through them all w/o finding it */
		if ( ! found ) {
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	/* if no values remain, delete the entire attribute */
	if ( BER_BVISNULL( &a->a_vals[ 0 ] ) ) {
		/* should already be zero */
		*newlevel = 0;
		
		if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	return LDAP_SUCCESS;
}

static int
replace_values( Entry *e, Modification *mod, int *newlevel )
{
	int rc;

	*newlevel = 0;
	rc = check_constraints( mod, newlevel );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rc = attr_delete( &e->e_attrs, mod->sm_desc );

	if ( rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_ATTRIBUTE ) {
		return rc;
	}

	if ( mod->sm_values != NULL ) {
		rc = attr_merge( e, mod->sm_desc, mod->sm_values, mod->sm_nvalues );
		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}
	}

	return LDAP_SUCCESS;
}


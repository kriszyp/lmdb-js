/* log.c - deal with log subsystem */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from
 *    flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 * 
 * 4. This notice may not be removed or altered.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>

#include "slap.h"
#include "lutil.h"
#include "ldif.h"
#include "back-monitor.h"

/*
 * log mutex
 */
ldap_pvt_thread_mutex_t		monitor_log_mutex;

static struct {
	int i;
	const char *s;
} int_2_level[] = {
	{ LDAP_DEBUG_TRACE,	"Trace" },
	{ LDAP_DEBUG_PACKETS,	"Packets" },
	{ LDAP_DEBUG_ARGS,	"Args" },
	{ LDAP_DEBUG_CONNS,	"Conns" },
	{ LDAP_DEBUG_BER,	"BER" },
	{ LDAP_DEBUG_FILTER,	"Filter" },
	{ LDAP_DEBUG_CONFIG,	"Config" },	/* useless */
	{ LDAP_DEBUG_ACL,	"ACL" },
	{ LDAP_DEBUG_STATS,	"Stats" },
	{ LDAP_DEBUG_STATS2,	"Stats2" },
	{ LDAP_DEBUG_SHELL,	"Shell" },
	{ LDAP_DEBUG_PARSE,	"Parse" },
	{ LDAP_DEBUG_CACHE,	"Cache" },
	{ LDAP_DEBUG_INDEX,	"Index" },
	{ 0,			NULL }
};

static int loglevel2int( const char *str );
static const char * int2loglevel( int n );

static int add_values( Entry *e, Modification *mod, int *newlevel );
static int delete_values( Entry *e, Modification *mod, int *newlevel );
static int replace_values( Entry *e, Modification *mod, int *newlevel );

/*
 * initializes log subentry
 */
int
monitor_subsys_log_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e;
	int			i;
	struct berval 		bv[2];

	ldap_pvt_thread_mutex_init( &monitor_log_mutex );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, &monitor_subsys[SLAPD_MONITOR_LOG].mss_ndn, 
				&e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_log_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_LOG].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_log_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_LOG].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	bv[1].bv_val = NULL;

	/* initialize the debug level */
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( int_2_level[ i ].i & ldap_syslog ) {
			bv[0].bv_val = ( char * )int_2_level[ i ].s;
			bv[0].bv_len = strlen( bv[0].bv_val );

			attr_merge( e, monitor_ad_desc, bv );
		}
	}

	monitor_cache_release( mi, e );

	return( 0 );
}

int 
monitor_subsys_log_modify( 
	struct monitorinfo 	*mi,
	Entry 			*e,
	Modifications		*modlist
)
{
	int		rc = LDAP_OTHER;
	int		newlevel = ldap_syslog;
	Attribute	*save_attrs;
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
			rc = attr_merge( e, mod->sm_desc, mod->sm_bvalues );
			if ( rc != 0 ) {
				rc = LDAP_OTHER;
				break;
			}
			continue;

		/*
		 * only the monitor description attribute can be modified
		 */
		} else if ( mod->sm_desc != monitor_ad_desc ) {
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
			rc = LDAP_OPERATIONS_ERROR;
			break;
		}

		if ( rc != LDAP_SUCCESS ) {
			break;
		}
	}

	/* set the new debug level */
	if ( rc == LDAP_SUCCESS ) {
		const char *text;
		static char textbuf[1024];

#if 0 	/* need op */
		/* check for abandon */
		ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
		if ( op->o_abandon ) {
			ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
			rc = SLAPD_ABANDON;

			goto cleanup;
		}
#endif

		/* check that the entry still obeys the schema */
		rc = entry_schema_check( be_monitor, e, save_attrs, 
				&text, textbuf, sizeof( textbuf ) );
		if ( rc != LDAP_SUCCESS ) {
			goto cleanup;
		}

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
loglevel2int( const char *str )
{
	int		i;
	
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( strcasecmp( str, int_2_level[ i ].s ) == 0 ) {
			return int_2_level[ i ].i;
		}
	}

	return 0;
}

static const char *
int2loglevel( int n )
{
	int		i;
	
	for ( i = 0; int_2_level[ i ].i != 0; i++ ) {
		if ( int_2_level[ i ].i == n ) {
			return int_2_level[ i ].s;
		}
	}

	return NULL;
}

static int
check_constraints( Modification *mod, int *newlevel )
{
	int		i;

	for ( i = 0; mod->sm_bvalues && mod->sm_bvalues[i].bv_val != NULL; i++ ) {
		int l;
		const char *s;
		ber_len_t len;
		
		l = loglevel2int( mod->sm_bvalues[i].bv_val );
		if ( !l ) {
			return LDAP_CONSTRAINT_VIOLATION;
		}

		s = int2loglevel( l );
		len = strlen( s );
		assert( len == mod->sm_bvalues[i].bv_len );
		
		AC_MEMCPY( mod->sm_bvalues[i].bv_val, s, len );

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

		for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
			int rc;
			int j;
			const char *text = NULL;
			struct berval asserted;

			rc = value_normalize( mod->sm_desc,
					SLAP_MR_EQUALITY,
					&mod->sm_bvalues[i],
					&asserted,
					&text );

			if ( rc != LDAP_SUCCESS ) {
				return rc;
			}

			for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
				int match;
				int rc = value_match( &match, mod->sm_desc, mr,
						SLAP_MR_VALUE_SYNTAX_MATCH,
						&a->a_vals[j], &asserted, &text );

				if ( rc == LDAP_SUCCESS && match == 0 ) {
					free( asserted.bv_val );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}

			free( asserted.bv_val );
		}
	}

	/* no - add them */
	if ( attr_merge( e, mod->sm_desc, mod->sm_bvalues ) != 0 ) {
		/* this should return result of attr_merge */
		return LDAP_OTHER;
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
	if ( mod->sm_bvalues == NULL ) {
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
	for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
		int rc;
		const char *text = NULL;

		struct berval asserted;

		rc = value_normalize( mod->sm_desc,
				SLAP_MR_EQUALITY,
				&mod->sm_bvalues[i],
				&asserted,
				&text );

		if( rc != LDAP_SUCCESS ) return rc;

		found = 0;
		for ( j = 0; a->a_vals[j].bv_val != NULL; j++ ) {
			int match;
			int rc = value_match( &match, mod->sm_desc, mr,
					SLAP_MR_VALUE_SYNTAX_MATCH,
					&a->a_vals[j], &asserted, &text );

			if( rc == LDAP_SUCCESS && match != 0 ) {
				continue;
			}

			/* found a matching value */
			found = 1;

			/* delete it */
			free( a->a_vals[j].bv_val );
			for ( k = j + 1; a->a_vals[k].bv_val != NULL; k++ ) {
				a->a_vals[k - 1] = a->a_vals[k];
			}
			a->a_vals[k - 1].bv_val = NULL;

			break;
		}

		free( asserted.bv_val );

		/* looked through them all w/o finding it */
		if ( ! found ) {
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	/* if no values remain, delete the entire attribute */
	if ( a->a_vals[0].bv_val == NULL ) {
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

	if ( mod->sm_bvalues != NULL &&
		attr_merge( e, mod->sm_desc, mod->sm_bvalues ) != 0 ) {
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}


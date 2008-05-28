/* repl.c - log modifications for replication purposes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
#include <ac/ctype.h>
#include <ac/socket.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "slap.h"
#include "ldif.h"

int
add_replica_info(
	Backend		*be,
	const char	*uri, 
	const char	*host )
{
	int i = 0;

	assert( be != NULL );
	assert( host != NULL );

	if ( be->be_replica != NULL ) {
		for ( ; be->be_replica[ i ] != NULL; i++ );
	}
		
	be->be_replica = ch_realloc( be->be_replica, 
		sizeof( struct slap_replica_info * )*( i + 2 ) );

	be->be_replica[ i ] 
		= ch_calloc( sizeof( struct slap_replica_info ), 1 );
	ber_str2bv( uri, 0, 0, &be->be_replica[ i ]->ri_bindconf.sb_uri );
	be->be_replica[ i ]->ri_host = host;
	be->be_replica[ i ]->ri_nsuffix = NULL;
	be->be_replica[ i ]->ri_attrs = NULL;
	be->be_replica[ i + 1 ] = NULL;

	return( i );
}

int
destroy_replica_info(
	Backend		*be )
{
	int i = 0;

	assert( be != NULL );

	if ( be->be_replica == NULL ) {
		return 0;
	}

	for ( ; be->be_replica[ i ] != NULL; i++ ) {
		ber_bvarray_free( be->be_replica[ i ]->ri_nsuffix );

		if ( be->be_replica[ i ]->ri_attrs ) {
			AttributeName	*an = be->be_replica[ i ]->ri_attrs;
			int		j;

			for ( j = 0; !BER_BVISNULL( &an[ j ].an_name ); j++ )
			{
				ch_free( an[ j ].an_name.bv_val );
			}
			ch_free( an );
		}

		bindconf_free( &be->be_replica[ i ]->ri_bindconf );

		ch_free( be->be_replica[ i ] );
	}

	ch_free( be->be_replica );

	return 0;
}

int
add_replica_suffix(
    Backend     *be,
    int		nr,
    const char  *suffix
)
{
	struct berval dn, ndn;
	int rc;

	dn.bv_val = (char *) suffix;
	dn.bv_len = strlen( dn.bv_val );

	rc = dnNormalize( 0, NULL, NULL, &dn, &ndn, NULL );
	if( rc != LDAP_SUCCESS ) {
		return 2;
	}

	if ( select_backend( &ndn, 0, 0 ) != be ) {
		free( ndn.bv_val );
		return 1;
	}

	ber_bvarray_add( &be->be_replica[nr]->ri_nsuffix, &ndn );
	return 0;
}

int
add_replica_attrs(
	Backend	*be,
	int	nr,
	char	*attrs,
	int	exclude
)
{
	if ( be->be_replica[nr]->ri_attrs != NULL ) {
		if ( be->be_replica[nr]->ri_exclude != exclude ) {
			fprintf( stderr, "attr selective replication directive '%s' conflicts with previous one (discarded)\n", attrs );
			ch_free( be->be_replica[nr]->ri_attrs );
			be->be_replica[nr]->ri_attrs = NULL;
		}
	}

	be->be_replica[nr]->ri_exclude = exclude;
	be->be_replica[nr]->ri_attrs = str2anlist( be->be_replica[nr]->ri_attrs,
		attrs, "," );
	return ( be->be_replica[nr]->ri_attrs == NULL );
}
   
static void
print_vals( FILE *fp, struct berval *type, struct berval *bv );
static void
replog1( struct slap_replica_info *ri, Operation *op, FILE *fp, long now);

void
replog( Operation *op )
{
	FILE	*fp, *lfp;
	int	i;
/* undef NO_LOG_WHEN_NO_REPLICAS */
#ifdef NO_LOG_WHEN_NO_REPLICAS
	int     count = 0;
#endif
	int	subsets = 0;
	long	now;
	char	*replogfile;

	replogfile = op->o_bd->be_replogfile ? op->o_bd->be_replogfile :
		frontendDB->be_replogfile;
	if ( !replogfile ) {
		return;
	}

	ldap_pvt_thread_mutex_lock( &replog_mutex );
	if ( (fp = lock_fopen( replogfile, "a", &lfp )) == NULL ) {
		ldap_pvt_thread_mutex_unlock( &replog_mutex );
		return;
	}

	now = slap_get_time();
	for ( i = 0; op->o_bd->be_replica != NULL && op->o_bd->be_replica[i] != NULL; i++ ) {
		/* check if dn's suffix matches legal suffixes, if any */
		if ( op->o_bd->be_replica[i]->ri_nsuffix != NULL ) {
			int j;

			for ( j = 0; op->o_bd->be_replica[i]->ri_nsuffix[j].bv_val; j++ ) {
				if ( dnIsSuffix( &op->o_req_ndn, &op->o_bd->be_replica[i]->ri_nsuffix[j] ) ) {
					break;
				}
			}

			if ( !op->o_bd->be_replica[i]->ri_nsuffix[j].bv_val ) {
				/* do not add "replica:" line */
				continue;
			}
		}
		/* See if we only want a subset of attributes */
		if ( op->o_bd->be_replica[i]->ri_attrs != NULL &&
			( op->o_tag == LDAP_REQ_MODIFY || op->o_tag == LDAP_REQ_ADD || op->o_tag == LDAP_REQ_EXTENDED ) ) {
			if ( !subsets ) {
				subsets = i + 1;
			}
			/* Do attribute subsets by themselves in a second pass */
			continue;
		}

		fprintf( fp, "replica: %s\n", op->o_bd->be_replica[i]->ri_host );
#ifdef NO_LOG_WHEN_NO_REPLICAS
		++count;
#endif
	}

#ifdef NO_LOG_WHEN_NO_REPLICAS
	if ( count == 0 && subsets == 0 ) {
		/* if no replicas matched, drop the log 
		 * (should we log it anyway?) */
		lock_fclose( fp, lfp );
		ldap_pvt_thread_mutex_unlock( &replog_mutex );

		return;
	}
#endif

	replog1( NULL, op, fp, now );

	if ( subsets > 0 ) {
		for ( i = subsets - 1; op->o_bd->be_replica[i] != NULL; i++ ) {

			/* If no attrs, we already did this above */
			if ( op->o_bd->be_replica[i]->ri_attrs == NULL ) {
				continue;
			}

			/* check if dn's suffix matches legal suffixes, if any */
			if ( op->o_bd->be_replica[i]->ri_nsuffix != NULL ) {
				int j;

				for ( j = 0; op->o_bd->be_replica[i]->ri_nsuffix[j].bv_val; j++ ) {
					if ( dnIsSuffix( &op->o_req_ndn, &op->o_bd->be_replica[i]->ri_nsuffix[j] ) ) {
						break;
					}
				}

				if ( !op->o_bd->be_replica[i]->ri_nsuffix[j].bv_val ) {
					/* no matching suffix found, skip it */
					continue;
				}
			}
			switch( op->o_tag ) {
			case LDAP_REQ_EXTENDED:
				/* quick hack for extended operations */
				/* assume change parameter is a Modifications* */
				/* fall thru */
			case LDAP_REQ_MODIFY:
			case LDAP_REQ_ADD:
				break;
			default:
				/* Other operations were logged in the first pass */
				continue;
			}
			replog1( op->o_bd->be_replica[i], op, fp, now );
		}
	}

	lock_fclose( fp, lfp );
	ldap_pvt_thread_mutex_unlock( &replog_mutex );
}

static void
rephdr(
	struct slap_replica_info *ri,
	Operation *op,
	FILE *fp,
	long now
)
{
	if ( ri ) {
		fprintf( fp, "replica: %s\n", ri->ri_host );
	}
	fprintf( fp, "time: %ld\n", now );
	fprintf( fp, "dn: %s\n", op->o_req_dn.bv_val );
}

static void
replog1(
	struct slap_replica_info *ri,
	Operation *op,
	FILE	*fp,
	long	now
)
{
	Modifications	*ml;
	Attribute	*a;
	AttributeName	*an;
	int		dohdr = 1, ocs = -1;
	struct berval vals[2];

	vals[1].bv_val = NULL;
	vals[1].bv_len = 0;

	switch ( op->o_tag ) {
	case LDAP_REQ_EXTENDED:
		/* quick hack for extended operations */
		/* assume change parameter is a Modifications* */
		/* fall thru */

	case LDAP_REQ_MODIFY:
		for ( ml = op->orm_modlist; ml != NULL; ml = ml->sml_next ) {
			char *did = NULL, *type = ml->sml_desc->ad_cname.bv_val;
			switch ( ml->sml_op ) {
			case LDAP_MOD_ADD:
				did = "add"; break;

			case LDAP_MOD_DELETE:
				did = "delete"; break;

			case LDAP_MOD_REPLACE:
				did = "replace"; break;

			case LDAP_MOD_INCREMENT:
				did = "increment"; break;
			}
			if ( ri && ri->ri_attrs ) {
				int is_in = ad_inlist( ml->sml_desc, ri->ri_attrs );

				/* skip if:
				 *   1) the attribute is not in the list,
				 *      and it's not an exclusion list
				 *   2) the attribute is in the list
				 *      and it's an exclusion list,
				 *      and either the objectClass attribute
				 *      has already been dealt with or
				 *      this is not the objectClass attr
				 */
				if ( ( !is_in && !ri->ri_exclude )
					|| ( ( is_in && ri->ri_exclude )
						&& ( !ocs || ml->sml_desc != slap_schema.si_ad_objectClass ) ) )
				{
					continue;
				}

				/* If this is objectClass, see if the value is included
				 * in any subset, otherwise drop it.
				 */
				if ( ocs && ml->sml_desc == slap_schema.si_ad_objectClass
					&& ml->sml_values )
				{
					int i, first = 1;

					if ( ocs == -1 ) ocs = 0;

					for ( i=0; ml->sml_values[i].bv_val; i++ ) {
						int match = 0;
						for ( an = ri->ri_attrs; an->an_name.bv_val; an++ ) {
							if ( an->an_oc ) {
								struct berval	bv = an->an_name;

								ocs = 1;
								match |= an->an_oc_exclude;

								switch ( bv.bv_val[ 0 ] ) {
								case '@':
								case '+':
								case '!':
									bv.bv_val++;
									bv.bv_len--;
									break;
								}

								if ( ml->sml_values[i].bv_len == bv.bv_len
									&& !strcasecmp(ml->sml_values[i].bv_val,
										bv.bv_val ) )
								{
									match = !an->an_oc_exclude;
									break;
								}
							}
						}
						/* Objectclasses need no special treatment, drop into
						 * regular processing
						 */
						if ( !ocs ) break;

						match ^= ri->ri_exclude;
						/* Found a match, log it */
						if ( match ) {
							if ( dohdr ) {
								rephdr( ri, op, fp, now );
								fprintf( fp, "changetype: modify\n" );
								dohdr = 0;
							}
							if ( first ) {
								fprintf( fp, "%s: %s\n", did, type );
								first = 0;
							}
							vals[0] = ml->sml_values[i];
							print_vals( fp, &ml->sml_desc->ad_cname, vals );
							ocs = 2;
						}

					}
					/* Explicit objectclasses have been handled already */
					if ( ocs ) {
						if ( ocs == 2 ) {
							fprintf( fp, "-\n" );
						}
						continue;
					}
				}
			}
			if ( dohdr ) {
				rephdr( ri, op, fp, now );
				fprintf( fp, "changetype: modify\n" );
				dohdr = 0;
			}
			fprintf( fp, "%s: %s\n", did, type );
			if ( ml->sml_values ) {
				print_vals( fp, &ml->sml_desc->ad_cname, ml->sml_values );
			}
			fprintf( fp, "-\n" );
		}
		break;

	case LDAP_REQ_ADD:
		for ( a = op->ora_e->e_attrs ; a != NULL; a=a->a_next ) {
			if ( ri && ri->ri_attrs ) {
				int is_in = ad_inlist( a->a_desc, ri->ri_attrs );

				/* skip if:
				 *   1) the attribute is not in the list,
				 *      and it's not an exclusion list
				 *   2) the attribute is in the list
				 *      and it's an exclusion list,
				 *      and either the objectClass attribute
				 *      has already been dealt with or
				 *      this is not the objectClass attr
				 */
				if ( ( !is_in && !ri->ri_exclude )
					|| ( ( is_in && ri->ri_exclude )
						&& ( !ocs || a->a_desc != slap_schema.si_ad_objectClass ) ) )
				{
					continue;
				}

				/* If the list includes objectClass names,
				 * only include those classes in the
				 * objectClass attribute
				 */
				if ( ocs && a->a_desc == slap_schema.si_ad_objectClass ) {
					int i;

					if ( ocs == -1 ) ocs = 0;

					for ( i=0; a->a_vals[i].bv_val; i++ ) {
						int match = 0;
						for ( an = ri->ri_attrs; an->an_name.bv_val; an++ ) {
							if ( an->an_oc ) {
								struct berval	bv = an->an_name;

								ocs = 1;
								match |= an->an_oc_exclude;

								switch ( bv.bv_val[ 0 ] ) {
								case '@':
								case '+':
								case '!':
									bv.bv_val++;
									bv.bv_len--;
									break;
								}

								if ( a->a_vals[i].bv_len == bv.bv_len
									&& !strcasecmp(a->a_vals[i].bv_val,
										bv.bv_val ) )
								{
									match = !an->an_oc_exclude;
									break;
								}
							}
						}
						if ( !ocs ) break;

						match ^= ri->ri_exclude;
						if ( match ) {
							if ( dohdr ) {
								rephdr( ri, op, fp, now );
								fprintf( fp, "changetype: add\n" );
								dohdr = 0;
							}
							vals[0] = a->a_nvals[i];
							print_vals( fp, &a->a_desc->ad_cname, vals );
						}
					}
					if ( ocs ) continue;
				}
			}
			if ( dohdr ) {
				rephdr( ri, op, fp, now );
				fprintf( fp, "changetype: add\n" );
				dohdr = 0;
			}
			print_vals( fp, &a->a_desc->ad_cname, a->a_vals );
		}
		break;

	case LDAP_REQ_DELETE:
		rephdr( ri, op, fp, now );
		fprintf( fp, "changetype: delete\n" );
		break;

	case LDAP_REQ_MODRDN:
		rephdr( ri, op, fp, now );
		fprintf( fp, "changetype: modrdn\n" );
		fprintf( fp, "newrdn: %s\n", op->orr_newrdn.bv_val );
		fprintf( fp, "deleteoldrdn: %d\n", op->orr_deleteoldrdn ? 1 : 0 );
		if( op->orr_newSup != NULL ) {
			fprintf( fp, "newsuperior: %s\n", op->orr_newSup->bv_val );
		}
	}
	fprintf( fp, "\n" );
}

static void
print_vals(
	FILE *fp,
	struct berval *type,
	struct berval *bv )
{
	ber_len_t i, len;
	char	*buf, *bufp;

	for ( i = 0, len = 0; bv && bv[i].bv_val; i++ ) {
		if ( bv[i].bv_len > len )
			len = bv[i].bv_len;
	}

	len = LDIF_SIZE_NEEDED( type->bv_len, len ) + 1;
	buf = (char *) ch_malloc( len );

	for ( ; bv && bv->bv_val; bv++ ) {
		bufp = buf;
		ldif_sput( &bufp, LDIF_PUT_VALUE, type->bv_val,
				    bv->bv_val, bv->bv_len );
		*bufp = '\0';

		fputs( buf, fp );

	}
	free( buf );
}

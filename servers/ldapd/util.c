/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
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

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include <sys/ioctl.h>

#include <quipu/commonarg.h>
#include <quipu/ds_error.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

/*
 * Print arbitrary stuff, for debugging.
 */


#define BPLEN	48

void
bprint( char *data, int len )
{
    static const char	hexdig[] = "0123456789abcdef";
    char	out[ BPLEN ];
    int		i = 0;

    (void) memset( out, 0, BPLEN );
    for ( ;; ) {
	if ( len < 1 ) {
	    printf( "\t%s\n", ( i == 0 ) ? "(end)" : out );
	    break;
	}

	if ( isgraph( (unsigned char)*data )) {
	    out[ i ] = ' ';
	    out[ i+1 ] = *data;
	} else {
	    out[ i ] = hexdig[ ( (unsigned char)*data & 0xf0 ) >> 4 ];
	    out[ i+1 ] = hexdig[ (unsigned char)*data & 0x0f ];
	}
	i += 2;
	len--;
	data++;

	if ( i > BPLEN - 2 ) {
	    printf( "\t%s\n", out );
	    (void) memset( out, 0, BPLEN );
	    i = 0;
	    continue;
	}
	out[ i++ ] = ' ';
    }
}

void
charlist_free( char **cl )
{
	int	i;

	if ( cl == NULL )
		return;

	for ( i = 0; cl[i] != NULL; i++ )
		free( cl[i] );
	free( (char *) cl );
}

int
get_ava( BerElement *ber, AVA *tava )
{
	char			*type, *value;

	Debug( LDAP_DEBUG_TRACE, "get_ava\n", 0, 0, 0 );

	/*
	 * An AVA looks like this:
	 *	AttributeValueAsertion ::= SEQUENCE {
	 *		attributeType	AttributeType,
	 *		attributeValue	AttributeValue
	 *	}
	 */

	if ( ber_scanf( ber, "{aa}", &type, &value ) == LBER_ERROR )
		return( LDAP_PROTOCOL_ERROR );

	if ( (tava->ava_type = str2AttrT( type )) == NULLAttrT ) {
		free( type );
		free( value );
		return( LDAP_UNDEFINED_TYPE );
	}

	if ( (tava->ava_value = ldap_str2AttrV( value,
	    tava->ava_type->oa_syntax )) == NULLAttrV ) {
		free( type );
		free( value );
		return( LDAP_INVALID_SYNTAX );
	}

	free( type );
	free( value );

	return( 0 );
}

int
chase_referral(
    Sockbuf		*clientsb,
    struct msg		*m,
    struct DSError	*err,
    char		**matched
)
{
	ContinuationRef		cr;
	struct access_point	*ap;
	int			rc, bound;
	struct conn		*save, *dup, *found;

	Debug( LDAP_DEBUG_TRACE, "chase_referral\n", 0, 0, 0 );

	save = m->m_conn;
	dup = conn_dup( m->m_conn );
	m->m_conn = dup;
	m->m_conn->c_ad = -1;

	/* for each dsa candidate */
	rc = LDAP_OTHER;
	for ( cr = err->ERR_REFERRAL.DSE_ref_candidates;
	    cr != NULLCONTINUATIONREF; cr = cr->cr_next ) {

		/* for each access point listed for the dsa */
		for ( ap = cr->cr_accesspoints; ap != NULLACCESSPOINT;
		    ap = ap->ap_next ) {
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				char	*str;

				str = paddr2str( ap->ap_address, NULLNA );
				fprintf( stderr, "Referring to (%s)...\n",
				    str );
			}
#endif

			if ( m->m_conn->c_paddr )
				free( (char *) m->m_conn->c_paddr );
			m->m_conn->c_paddr = psap_cpy( ap->ap_address );

			if ( (found = conn_find( m->m_conn )) != NULL ) {
				conn_free( m->m_conn );
				m->m_conn = found;
				m->m_conn->c_refcnt++;
				conn_free( save );
				return( LDAP_SUCCESS );
			}

			rc = do_bind_real( m->m_conn, &bound, matched );

			if ( rc == LDAP_SUCCESS ) {
				conn_free( save );
				conn_add( m->m_conn );
				return( LDAP_SUCCESS );
			}
		}

	}

	/* so the conn can be found and freed later */
	conn_free( m->m_conn );
	m->m_conn = save;

	return( rc );
}

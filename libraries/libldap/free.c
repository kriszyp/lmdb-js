/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1994 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  free.c - some free routines are included here to avoid having to
 *           link in lots of extra code when not using certain features
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * C-API deallocator
 */
void
ldap_memfree( void *p )
{
	LDAP_FREE( p );
}

void
ldap_memvfree( void **v )
{
	LDAP_VFREE( v );
}

void *
ldap_memalloc( ber_len_t s )
{
	return LDAP_MALLOC( s );
}

void *
ldap_memcalloc( ber_len_t n, ber_len_t s )
{
	return LDAP_CALLOC( n, s );
}

void *
ldap_memrealloc( void* p, ber_len_t s )
{
	return LDAP_REALLOC( p, s );
}

char *
ldap_strdup( LDAP_CONST char *p )
{
	return LDAP_STRDUP( p );
}

void
ldap_getfilter_free( LDAPFiltDesc *lfdp )
{
    LDAPFiltList	*flp, *nextflp;
    LDAPFiltInfo	*fip, *nextfip;

    for ( flp = lfdp->lfd_filtlist; flp != NULL; flp = nextflp ) {
	for ( fip = flp->lfl_ilist; fip != NULL; fip = nextfip ) {
	    nextfip = fip->lfi_next;
	    LDAP_FREE( fip->lfi_filter );
	    LDAP_FREE( fip->lfi_desc );
	    LDAP_FREE( fip );
	}
	nextflp = flp->lfl_next;
	LDAP_FREE( flp->lfl_pattern );
	LDAP_FREE( flp->lfl_delims );
	LDAP_FREE( flp->lfl_tag );
	LDAP_FREE( flp );
    }

    if ( lfdp->lfd_curvalcopy != NULL ) {
	LDAP_FREE( lfdp->lfd_curvalcopy );
    }
    if ( lfdp->lfd_curvalwords != NULL ) {
	LDAP_FREE( lfdp->lfd_curvalwords );
    }
    if ( lfdp->lfd_filtprefix != NULL ) {
	LDAP_FREE( lfdp->lfd_filtprefix );
    }
    if ( lfdp->lfd_filtsuffix != NULL ) {
	LDAP_FREE( lfdp->lfd_filtsuffix );
    }

    LDAP_FREE( lfdp );
}

/*
 * free a null-terminated array of pointers to mod structures. the
 * structures are freed, not the array itself, unless the freemods
 * flag is set.
 */

void
ldap_mods_free( LDAPMod **mods, int freemods )
{
	int	i;

	if ( mods == NULL )
		return;

	for ( i = 0; mods[i] != NULL; i++ ) {
		if ( mods[i]->mod_op & LDAP_MOD_BVALUES ) {
			if( mods[i]->mod_bvalues != NULL )
				ber_bvecfree( mods[i]->mod_bvalues );

		} else if( mods[i]->mod_values != NULL ) {
			LDAP_VFREE( mods[i]->mod_values );
		}

		if ( mods[i]->mod_type != NULL ) {
			LDAP_FREE( mods[i]->mod_type );
		}

		LDAP_FREE( (char *) mods[i] );
	}

	if ( freemods ) {
		LDAP_FREE( (char *) mods );
	}
}

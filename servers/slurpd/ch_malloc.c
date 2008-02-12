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
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).
 */

#define CH_FREE 1

/*
 * ch_malloc.c - malloc() and friends, with check for NULL return.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/socket.h>

#include "../slapd/slap.h"


#ifndef CSRIMALLOC

/*
 * Just like malloc, except we check the returned value and exit
 * if anything goes wrong.
 */
void *
ch_malloc(
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) ber_memalloc( size )) == NULL ) {
		fprintf( stderr, "malloc of %lu bytes failed\n",
			(long) size );
		exit( EXIT_FAILURE );
	}

	return( new );
}




/*
 * Just like realloc, except we check the returned value and exit
 * if anything goes wrong.
 */
void *
ch_realloc(
    void		*block,
    ber_len_t	size
)
{
	void	*new;

	if ( block == NULL ) {
		return( ch_malloc( size ) );
	}

	if ( size == 0 ) {
		ch_free( block );
	}

	if ( (new = (void *) ber_memrealloc( block, size )) == NULL ) {
		fprintf( stderr, "realloc of %lu bytes failed\n",
			(long) size );
		exit( EXIT_FAILURE );
	}

	return( new );
}




/*
 * Just like calloc, except we check the returned value and exit
 * if anything goes wrong.
 */
void *
ch_calloc(
    ber_len_t	nelem,
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) ber_memcalloc( nelem, size )) == NULL ) {
		fprintf( stderr, "calloc of %lu elems of %lu bytes failed\n",
		    (long) nelem, (long) size );
		exit( EXIT_FAILURE );
	}

	return( new );
}

/*
 * Just like strdup, except we check the returned value and exit
 * if anything goes wrong.
 */
char *
ch_strdup(
    const char *string
)
{
	char	*new;

	if ( (new = ber_strdup( string )) == NULL ) {
		fprintf( stderr, "ch_strdup: duplication of \"%s\" failed\n",
				string );
		exit( EXIT_FAILURE );
	}

	return( new );
}

/*
 * Just like free, except we check to see if p is null.
 */
void
ch_free(
    void *p
)
{
    if ( p != NULL ) {
		ber_memfree( p );
    }
    return;
}

#endif

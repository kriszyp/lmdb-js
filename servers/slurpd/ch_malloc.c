/*
 * Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/*
 * ch_malloc.c - malloc() and friends, with check for NULL return.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/socket.h>

#include "../slapd/slap.h"



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

	if ( (new = (void *) malloc( size )) == NULL ) {
		fprintf( stderr, "malloc of %lu bytes failed\n",
			(long) size );
		exit( 1 );
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

	if ( (new = (void *) realloc( block, size )) == NULL ) {
		fprintf( stderr, "realloc of %lu bytes failed\n",
			(long) size );
		exit( 1 );
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

	if ( (new = (void *) calloc( nelem, size )) == NULL ) {
		fprintf( stderr, "calloc of %lu elems of %lu bytes failed\n",
		    (long) nelem, (long) size );
		exit( 1 );
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
	free( p );
    }
    return;
}
	

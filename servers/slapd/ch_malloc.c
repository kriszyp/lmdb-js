/* ch_malloc.c - malloc routines that test returns from malloc and friends */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

void *
ch_malloc(
    unsigned long	size
)
{
	void	*new;

	if ( (new = (void *) malloc( size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "malloc of %d bytes failed\n", size, 0, 0 );
		exit( 1 );
	}

	return( new );
}

void *
ch_realloc(
    void		*block,
    unsigned long	size
)
{
	void	*new;

	if ( block == NULL ) {
		return( ch_malloc( size ) );
	}

	if ( (new = (void *) realloc( block, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "realloc of %d bytes failed\n", size, 0, 0 );
		exit( 1 );
	}

	return( new );
}

void *
ch_calloc(
    unsigned long	nelem,
    unsigned long	size
)
{
	void	*new;

	if ( (new = (void *) calloc( nelem, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "calloc of %d elems of %d bytes failed\n",
		  nelem, size, 0 );
		exit( 1 );
	}

	return( new );
}

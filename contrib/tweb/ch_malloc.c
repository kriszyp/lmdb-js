/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* ch_malloc.c                                                              *
*                                                                          *
* Function:..Alloc-Functions with Error-Handling                           *
*                                                                          *
*            from LDAP3.2 University of Michigan                           *
*                                                                          *
*            Patch: unsigned long --> size_t fuer size-Parameter           *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            April 16 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            December 31 1998           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: ch_malloc.c,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "tglobal.h"

#include "ch_malloc_exp.h"
#include "support_exp.h"


/* ch_malloc.c - malloc routines that test returns from malloc and friends */

PUBLIC char * ch_malloc( size )
size_t size;
{
	char	*new;

	if ( (new = (char *) calloc(1, size )) == NULL ) {
		if (dosyslog) syslog( LOG_INFO, "malloc of %d bytes failed\n", size );
		exit_tweb( 1 );
	}

	return( new );
}
/* end of function: ch_malloc */

PUBLIC char * ch_realloc( block, size )
char		*block;
size_t size;
{
	char	*new;

	if ( block == NULL ) {
		return( ch_malloc( size ) );
	}

	if ( (new = (char *) realloc( block, size )) == NULL ) {
		if (dosyslog) syslog( LOG_INFO, "realloc of %d bytes failed\n", size );
		exit_tweb( 1 );
	}

	return( new );
}
/* end of function: ch_realloc */

PUBLIC char * ch_calloc( nelem, size )
size_t nelem;
size_t size;
{
	char	*new;

	if ( (new = (char *) calloc( nelem, size )) == NULL ) {
		if (dosyslog) syslog( LOG_INFO, "calloc of %d elems of %d bytes failed\n",
		  nelem, size );
		exit_tweb( 1 );
	}

	return( new );
}
/* end of function: ch_calloc */

/* stack.c - stack handling routines */

#include <stdio.h>
#include <time.h>
#include "lber.h"
#include "ldap.h"

#if defined( sunos4 )

#include <lwp/lwp.h>
#include <lwp/stackdep.h>

#define MAX_STACK	51200
#define MAX_THREADS	20

struct stackinfo {
	int		stk_inuse;
	stkalign_t	*stk_stack;
};

static struct stackinfo	*stacks;

stkalign_t *
get_stack( int *stacknop )
{
	int	i;

	if ( stacks == NULL ) {
		stacks = (struct stackinfo *) ch_calloc( 1, MAX_THREADS *
		    sizeof(struct stackinfo) );
	}

	for ( i = 0; i < MAX_THREADS; i++ ) {
		if ( stacks[i].stk_inuse == 0 ) {
			break;
		}
	}

	if ( i == MAX_THREADS ) {
		Debug( LDAP_DEBUG_ANY,
		    "no more stacks (max %d) - increase MAX_THREADS for more",
		    MAX_THREADS, 0, 0 );
		return( NULL );
	}

	if ( stacks[i].stk_stack == NULL ) {
		stacks[i].stk_stack = (stkalign_t *) malloc(
		    (MAX_STACK / sizeof(stkalign_t) + 1 )
		    * sizeof(stkalign_t) );
	}

	*stacknop = i;
	stacks[i].stk_inuse = 1;
	return( stacks[i].stk_stack + MAX_STACK / sizeof(stkalign_t) );
}

void
free_stack(
    int	stackno
)
{
	if ( stackno < 0 || stackno > MAX_THREADS ) {
		Debug( LDAP_DEBUG_ANY, "free_stack of bogus stack %d",
		    stackno, 0, 0 );
	}

	stacks[stackno].stk_inuse = 0;
}

#endif

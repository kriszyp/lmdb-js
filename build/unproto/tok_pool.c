/*++
/* NAME
/*	tok_pool 3
/* SUMMARY
/*	maintain pool of unused token structures
/* PACKAGE
/*	unproto
/* SYNOPSIS
/*	#include "token.h"
/*
/*	struct token *tok_alloc()
/*
/*	void tok_free(t)
/*	struct token *t;
/* DESCRIPTION
/*	tok_alloc() and tok_free() maintain a pool of unused token
/*	structures.
/*
/*	tok_alloc() takes the first free token structure from the pool
/*	or allocates a new one if the pool is empty.
/*
/*	tok_free() adds a (possibly composite) token structure to the pool.
/* BUGS
/*	The pool never shrinks.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/01/15 21:53:04
/* VERSION/RELEASE
/*	1.2
/*--*/

static char pool_sccsid[] = "@(#) tok_pool.c 1.2 92/01/15 21:53:04";

/* C library */

extern char *malloc();

/* Application-specific stuff */

#include "token.h"
#include "vstring.h"
#include "error.h"

#define	TOKLEN	5			/* initial string buffer length */

struct token *tok_pool = 0;		/* free token pool */

/* tok_alloc - allocate token structure from pool or heap */

struct token *tok_alloc()
{
    register struct token *t;

    if (tok_pool) {				/* re-use an old one */
	t = tok_pool;
	tok_pool = t->next;
    } else {					/* create a new one */
	if ((t = (struct token *) malloc(sizeof(struct token))) == 0
	    || (t->vstr = vs_alloc(TOKLEN)) == 0)
	    fatal("out of memory");
    }
    t->next = t->head = t->tail = 0;
#ifdef	DEBUG
    strcpy(t->vstr->str, "BUSY");
#endif
    return (t);
}

/* tok_free - return (possibly composite) token to pool of free tokens */

void    tok_free(t)
register struct token *t;
{
#ifdef DEBUG
    /* Check if we are freeing free token */

    register struct token *p;

    for (p = tok_pool; p; p = p->next)
	if (p == t)
	    fatal("freeing free token");
#endif

    /* Free neighbours and subordinates first */

    if (t->next)
	tok_free(t->next);
    if (t->head)
	tok_free(t->head);

    /* Free self */

    t->next = tok_pool;
    t->head = t->tail = 0;
    tok_pool = t;
#ifdef	DEBUG
    strcpy(t->vstr->str, "FREE");
#endif
}

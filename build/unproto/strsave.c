/*++
/* NAME
/*	strsave 3
/* SUMMARY
/*	maintain unique copy of a string
/* SYNOPSIS
/*	char *strsave(string)
/*	char *string;
/* DESCRIPTION
/*	This function returns a pointer to an unique copy of its
/*	argument.
/* DIAGNOSTISC
/*	strsave() calls fatal() when it runs out of memory.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/01/15 21:53:13
/* VERSION/RELEASE
/*	1.1
/*--*/

static char strsave_sccsid[] = "@(#) strsave.c 1.1 92/01/15 21:53:13";

/* C library */

extern char *strcpy();
extern char *malloc();

/* Application-specific stuff */

#include "error.h"

#define	STR_TABSIZE	100

struct string {
    char   *strval;			/* unique string copy */
    struct string *next;		/* next one in hash chain */
};

static struct string *str_tab[STR_TABSIZE] = {0,};

/* More string stuff. Maybe it should go to an #include file. */

#define	STREQ(x,y)	(*(x) == *(y) && strcmp((x),(y)) == 0)

/* strsave - save unique copy of string */

char   *strsave(str)
register char *str;
{
    register struct string *s;
    register int where = hash(str, STR_TABSIZE);

    /* Look for existing entry. */

    for (s = str_tab[where]; s; s = s->next)
	if (STREQ(str, s->strval))
	    return (s->strval);

    /* Add new entry. */

    if ((s = (struct string *) malloc(sizeof(*s))) == 0
	|| (s->strval = malloc(strlen(str) + 1)) == 0)
	fatal("out of memory");
    s->next = str_tab[where];
    str_tab[where] = s;
    return (strcpy(s->strval, str));
}

/*++
/* NAME
/*	symbol 3
/* SUMMARY
/*	rudimentary symbol table package
/* SYNOPSIS
/*	#include "symbol.h"
/*
/*	void sym_init()
/*
/*	void sym_enter(name, type)
/*	char *name;
/*	int type;
/*
/*	struct symbol *sym_find(name)
/*	char *name;
/* DESCRIPTION
/*	This is a rudimentary symbol-table package, just enough to
/*	keep track of a couple of C keywords.
/*
/*	sym_init() primes the table with C keywords. At present, most of
/*	the keywords that have to do with types are left out.
/*	We need a different strategy to detect type definitions because
/*	we do not keep track of typedef names.
/*
/*	sym_enter() adds an entry to the symbol table.
/*
/*	sym_find() locates a symbol table entry (it returns 0 if
/*	it is not found).
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/02/15 18:59:56
/* VERSION/RELEASE
/*	1.4
/*--*/

static char symbol_sccsid[] = "@(#) symbol.c 1.4 92/02/15 18:59:56";

/* C library */

extern char *strcpy();
extern char *malloc();

/* Application-specific stuff */

#include "error.h"
#include "token.h"
#include "symbol.h"

#define	SYM_TABSIZE	20

static struct symbol *sym_tab[SYM_TABSIZE] = {0,};

/* More string stuff. Maybe it should go to an #include file. */

#define	STREQ(x,y)	(*(x) == *(y) && strcmp((x),(y)) == 0)

/* sym_enter - enter symbol into table */

void    sym_enter(name, type)
char   *name;
int     type;
{
    struct symbol *s;
    int     where;

    if ((s = (struct symbol *) malloc(sizeof(*s))) == 0
	|| (s->name = malloc(strlen(name) + 1)) == 0)
	fatal("out of memory");
    (void) strcpy(s->name, name);
    s->type = type;

    where = hash(name, SYM_TABSIZE);
    s->next = sym_tab[where];
    sym_tab[where] = s;
}

/* sym_find - locate symbol definition */

struct symbol *sym_find(name)
register char *name;
{
    register struct symbol *s;

    /*
     * This function is called for almost every "word" token, so it better be
     * fast.
     */

    for (s = sym_tab[hash(name, SYM_TABSIZE)]; s; s = s->next)
	if (STREQ(name, s->name))
	    return (s);
    return (0);
}

 /*
  * Initialization data for symbol table. We do not enter keywords for types.
  * We use a different strategy to detect type declarations because we do not
  * keep track of typedef names.
  */

struct sym {
    char   *name;
    int     tokno;
};

static struct sym syms[] = {
    "if", TOK_CONTROL,
    "else", TOK_CONTROL,
    "for", TOK_CONTROL,
    "while", TOK_CONTROL,
    "do", TOK_CONTROL,
    "switch", TOK_CONTROL,
    "case", TOK_CONTROL,
    "default", TOK_CONTROL,
    "return", TOK_CONTROL,
    "continue", TOK_CONTROL,
    "break", TOK_CONTROL,
    "goto", TOK_CONTROL,
    "struct", TOK_COMPOSITE,
    "union", TOK_COMPOSITE,
    "__DATE__", TOK_DATE,
    "__TIME__", TOK_TIME,
#if defined(MAP_VOID_STAR) || defined(MAP_VOID)
    "void", TOK_VOID,
#endif
    "asm", TOK_OTHER,
    0,
};

/* sym_init - enter known keywords into symbol table */

void    sym_init()
{
    register struct sym *p;

    for (p = syms; p->name; p++)
	sym_enter(p->name, p->tokno);
}


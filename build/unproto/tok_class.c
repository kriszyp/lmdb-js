/*++
/* NAME
/*	tok_class 3
/* SUMMARY
/*	token classification
/* PACKAGE
/*	unproto
/* SYNOPSIS
/*	#include "token.h"
/*
/*	void tok_unget(t)
/*	struct token *t;
/*
/*	struct token *tok_class()
/* DESCRIPTION
/*	tok_class() collects single and composite tokens, and
/*	recognizes keywords.
/*	At present, the only composite tokens are ()-delimited,
/*	comma-separated lists, and non-whitespace tokens with attached
/*	whitespace or comment tokens.
/*
/*	Source transformations are: __DATE__ and __TIME__ are rewritten
/*	to string constants with the current date and time, respectively.
/*	Multiple string constants are concatenated. Optionally, "void *" 
/*	is mapped to "char *", and plain "void" to "int".
/*
/*	tok_unget() implements an arbitrary amount of token pushback.
/*	Only tokens obtained through tok_class() should be given to
/*	tok_unget(). This function accepts a list of tokens in 
/*	last-read-first order.
/* DIAGNOSTICS
/*	The code complains if input terminates in the middle of a list.
/* BUGS
/*	Does not preserve white space at the beginning of a list element
/*	or after the end of a list.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/01/15 21:53:02
/* VERSION/RELEASE
/*	1.4
/*--*/

static char class_sccsid[] = "@(#) tok_class.c 1.4 92/01/15 21:53:02";

/* C library */

#include <stdio.h>

extern char *strcpy();
extern long time();
extern char *ctime();

/* Application-specific stuff */

#include "error.h"
#include "vstring.h"
#include "token.h"
#include "symbol.h"

static struct token *tok_list();
static void tok_list_struct();
static void tok_list_append();
static void tok_strcat();
static void tok_time();
static void tok_date();
static void tok_space_append();

#if defined(MAP_VOID_STAR) || defined(MAP_VOID)
static void tok_void();			/* rewrite void keyword */
#endif

static struct token *tok_buf = 0;	/* token push-back storage */

/* TOK_PREPEND - add token to LIFO queue, return head */

#define TOK_PREPEND(list,t) (t->next = list, list = t)

/* tok_space_append - append trailing space except at start of or after list */

static void tok_space_append(list, t)
register struct token *list;
register struct token *t;
{

    /*
     * The head/tail fields of a token do triple duty. They are used to keep
     * track of the members that make up a (list); to keep track of the
     * non-blank tokens that make up one list member; and, finally, to tack
     * whitespace and comment tokens onto the non-blank tokens that make up
     * one list member.
     * 
     * Within a (list), white space and comment tokens are always tacked onto
     * the non-blank tokens to avoid parsing complications later on. For this
     * reason, blanks and comments at the beginning of a list member are
     * discarded because there is no token to tack them onto. (Well, we could
     * start each list member with a dummy token, but that would mess up the
     * whole unprototyper).
     * 
     * Blanks or comments that follow a (list) are discarded, because the
     * head/tail fields of a (list) are already being used for other
     * purposes.
     * 
     * Newlines within a (list) are discarded because they can mess up the
     * output when we rewrite function headers. The output routines will
     * regenerate discarded newlines, anyway.
     */

    if (list == 0 || list->tokno == TOK_LIST) {
	tok_free(t);
    } else {
	tok_list_append(list, t);
    }
}

/* tok_class - discriminate single tokens, keywords, and composite tokens */

struct token *tok_class()
{
    register struct token *t;
    register struct symbol *s;

    /*
     * Use push-back token, if available. Push-back tokens are already
     * canonical and can be passed on to the caller without further
     * inspection.
     */

    if (t = tok_buf) {
	tok_buf = t->next;
	t->next = 0;
	return (t);
    }
    /* Read a new token and canonicalize it. */

    if (t = tok_get()) {
	switch (t->tokno) {
	case '(':				/* beginning of list */
	    t = tok_list(t);
	    break;
	case TOK_WORD:				/* look up keyword */
	    if ((s = sym_find(t->vstr->str))) {
		switch (s->type) {
		case TOK_TIME:			/* map __TIME__ to string */
		    tok_time(t);
		    tok_strcat(t);		/* look for more strings */
		    break;
		case TOK_DATE:			/* map __DATE__ to string */
		    tok_date(t);
		    tok_strcat(t);		/* look for more strings */
		    break;
#if defined(MAP_VOID_STAR) || defined(MAP_VOID)
		case TOK_VOID:			/* optionally map void types */
		    tok_void(t);
		    break;
#endif
		default:			/* other keyword */
		    t->tokno = s->type;
		    break;
		}
	    }
	    break;
	case '"':				/* string, look for more */
	    tok_strcat(t);
	    break;
	}
    }
    return (t);
}

/* tok_list - collect ()-delimited, comma-separated list of tokens */

static struct token *tok_list(t)
struct token *t;
{
    register struct token *list = tok_alloc();
    char   *filename;
    int     lineno;

    /* Save context of '(' for diagnostics. */

    filename = t->path;
    lineno = t->line;

    list->tokno = TOK_LIST;
    list->head = list->tail = t;
    list->path = t->path;
    list->line = t->line;
#ifdef DEBUG
    strcpy(list->vstr->str, "LIST");
#endif

    /*
     * Read until the matching ')' is found, accounting for structured stuff
     * (enclosed by '{' and '}' tokens). Break the list up at each ',' token,
     * and try to preserve as much whitespace as possible. Newlines are
     * discarded so that they will not mess up the layout when we rewrite
     * argument lists. The output routines will regenerate discarded
     * newlines.
     */

    while (t = tok_class()) {			/* skip blanks */
	switch (t->tokno) {
	case ')':				/* end of list */
	    tok_list_append(list, t);
	    return (list);
	case '{':				/* struct/union type */
	    tok_list_struct(list->tail, t);
	    break;
	case TOK_WSPACE:			/* preserve trailing blanks */
	    tok_space_append(list->tail->tail, t);	/* except after list */
	    break;
	case '\n':				/* fix newlines later */
	    tok_free(t);
	    break;
	case ',':				/* list separator */
	    tok_list_append(list, t);
	    break;
	default:				/* other */
	    tok_list_append(list->tail, t);
	    break;
	}
    }
    error_where(filename, lineno, "unmatched '('");
    return (list);				/* do not waste any data */
}

/* tok_list_struct - collect structured type info within list */

static void tok_list_struct(list, t)
register struct token *list;
register struct token *t;
{
    char   *filename;
    int     lineno;

    /*
     * Save context of '{' for diagnostics. This routine is called by the one
     * that collects list members. If the '}' is not found, the list
     * collector will not see the closing ')' either.
     */

    filename = t->path;
    lineno = t->line;

    tok_list_append(list, t);

    /*
     * Collect tokens until the matching '}' is found. Try to preserve as
     * much whitespace as possible. Newlines are discarded so that they do
     * not interfere when rewriting argument lists. The output routines will
     * regenerate discarded newlines.
     */

    while (t = tok_class()) {
	switch (t->tokno) {
	case TOK_WSPACE:			/* preserve trailing blanks */
	    tok_space_append(list->tail, t);	/* except after list */
	    break;
	case '\n':				/* fix newlines later */
	    tok_free(t);
	    break;
	case '{':				/* recurse */
	    tok_list_struct(list, t);
	    break;
	case '}':				/* done */
	    tok_list_append(list, t);
	    return;
	default:				/* other */
	    tok_list_append(list, t);
	    break;
	}
    }
    error_where(filename, lineno, "unmatched '{'");
}

/* tok_strcat - concatenate multiple string constants */

static void tok_strcat(t1)
register struct token *t1;
{
    register struct token *t2;
    register struct token *lookahead = 0;

    /*
     * Read ahead past whitespace, comments and newlines. If we find a string
     * token, concatenate it with the previous one and push back the
     * intervening tokens (thus preserving as much information as possible).
     * If we find something else, push back all lookahead tokens.
     */

#define PUSHBACK_AND_RETURN { if (lookahead) tok_unget(lookahead); return; }

    while (t2 = tok_class()) {
	switch (t2->tokno) {
	case TOK_WSPACE:			/* read past comments/blanks */
	case '\n':				/* read past newlines */
	    TOK_PREPEND(lookahead, t2);
	    break;
	case '"':				/* concatenate string tokens */
	    if (vs_strcpy(t1->vstr,
			  t1->vstr->str + strlen(t1->vstr->str) - 1,
			  t2->vstr->str + 1) == 0)
		fatal("out of memory");
	    tok_free(t2);
	    PUSHBACK_AND_RETURN;
	default:				/* something else, push back */
	    tok_unget(t2);
	    PUSHBACK_AND_RETURN;
	}
    }
    PUSHBACK_AND_RETURN;			/* hit EOF */
}

#if defined(MAP_VOID_STAR) || defined(MAP_VOID)

/* tok_void - support for compilers that have problems with "void" */

static void tok_void(t)
register struct token *t;
{
    register struct token *t2;
    register struct token *lookahead = 0;

    /*
     * Look ahead beyond whitespace, comments and newlines until we see a '*'
     * token. If one is found, replace "void" by "char". If we find something
     * else, and if "void" should always be mapped, replace "void" by "int".
     * Always push back the lookahead tokens.
     * 
     * XXX The code also replaces the (void) argument list; this must be
     * accounted for later on. The alternative would be to add (in unproto.c)
     * TOK_VOID cases all over the place and that would be too error-prone.
     */

#define PUSHBACK_AND_RETURN { if (lookahead) tok_unget(lookahead); return; }

    while (t2 = tok_class()) {
	switch (TOK_PREPEND(lookahead, t2)->tokno) {
	case TOK_WSPACE:			/* read past comments/blanks */
	case '\n':				/* read past newline */
	    break;
	case '*':				/* "void *" -> "char *" */
	    if (vs_strcpy(t->vstr, t->vstr->str, "char") == 0)
		fatal("out of memory");
	    PUSHBACK_AND_RETURN;
	default:
#ifdef MAP_VOID					/* plain "void" -> "int" */
	    if (vs_strcpy(t->vstr, t->vstr->str, "int") == 0)
		fatal("out of memory");
#endif
	    PUSHBACK_AND_RETURN;
	}
    }
    PUSHBACK_AND_RETURN;			/* hit EOF */
}

#endif

/* tok_time - rewrite __TIME__ to "hh:mm:ss" string constant */

static void tok_time(t)
struct token *t;
{
    long    now;
    char   *cp;
    char    buf[BUFSIZ];

    /*
     * Using sprintf() to select parts of a string is gross, but this should
     * be fast enough.
     */

    (void) time(&now);
    cp = ctime(&now);
    sprintf(buf, "\"%.8s\"", cp + 11);
    if (vs_strcpy(t->vstr, t->vstr->str, buf) == 0)
	fatal("out of memory");
    t->tokno = buf[0];
}

/* tok_date - rewrite __DATE__ to "Mmm dd yyyy" string constant */

static void tok_date(t)
struct token *t;
{
    long    now;
    char   *cp;
    char    buf[BUFSIZ];

    /*
     * Using sprintf() to select parts of a string is gross, but this should
     * be fast enough.
     */

    (void) time(&now);
    cp = ctime(&now);
    sprintf(buf, "\"%.3s %.2s %.4s\"", cp + 4, cp + 8, cp + 20);
    if (vs_strcpy(t->vstr, t->vstr->str, buf) == 0)
	fatal("out of memory");
    t->tokno = buf[0];
}

/* tok_unget - push back one or more possibly composite tokens */

void    tok_unget(t)
register struct token *t;
{
    register struct token *next;

    do {
	next = t->next;
	TOK_PREPEND(tok_buf, t);
    } while (t = next);
}

/* tok_list_append - append data to list */

static void tok_list_append(h, t)
struct token *h;
struct token *t;
{
    if (h->head == 0) {
	h->head = h->tail = t;
    } else {
	h->tail->next = t;
	h->tail = t;
    }
}

/*++
/* NAME
/*	unproto 1
/* SUMMARY
/*	compile ANSI C with traditional UNIX C compiler
/* PACKAGE
/*	unproto
/* SYNOPSIS
/*	/somewhere/cpp ...
/*
/*	cc cflags -E file.c | unproto >file.i; cc cflags -c file.i
/* DESCRIPTION
/*	This document describes a filter that sits in between the UNIX
/*	C preprocessor and the next UNIX C compiler stage, on the fly rewriting
/*	ANSI-style syntax to old-style syntax. Typically, the program is
/*	invoked by the native UNIX C compiler as an alternate preprocessor.
/*	The unprototyper in turn invokes the native C preprocessor and
/*	massages its output. Similar tricks can be used with the lint(1)
/*	command.
/*
/*	Language constructs that are always rewritten:
/* .TP
/* function headings, prototypes, pointer types
/*	ANSI-C style function headings, function prototypes, function
/*	pointer types and type casts are rewritten to old style.
/*	<stdarg.h> support is provided for functions with variable-length
/*	argument lists.
/* .TP
/* character and string constants
/*	The \\a and \\x escape sequences are rewritten to their (three-digit)
/*	octal equivalents.
/*
/*	Multiple string tokens are concatenated; an arbitrary number of
/*	whitespace or comment tokens may appear between successive
/*	string tokens.
/*
/*	Within string constants, octal escape sequences are rewritten to the
/*	three-digit \\ddd form, so that string concatenation produces correct
/*	results.
/* .TP
/* date and time
/*	The __DATE__ and __TIME__ tokens are replaced by string constants
/*	of the form "Mmm dd yyyy" and "hh:mm:ss", respectively. The result
/*	is subjected to string concatenation, just like any other string
/*	constant.
/* .PP
/*	Language constructs that are rewritten only if the program has been
/*	configured to do so:
/* .TP
/* void types
/*	The unprototyper can be configured to rewrite "void *" to "char *",
/*	and even to rewrite plain "void" to "int".
/*	These features are configurable because many traditional UNIX C
/*	compilers do not need them.
/*
/*	Note: (void) argument lists are always replaced by empty ones.
/* .PP
/*	ANSI C constructs that are not rewritten because the traditional
/*	UNIX C preprocessor provides suitable workarounds:
/* .TP
/* const and volatile
/*	Use the "-Dconst=" and/or "-Dvolatile=" preprocessor directives to
/*	get rid of unimplemented keywords.
/* .TP
/* token pasting and stringizing
/*	The traditional UNIX C preprocessor provides excellent alternatives.
/*	For example:
/*
/* .nf
/* .ne 2
/*	#define	string(bar)	"bar"		/* instead of: # x */
/*	#define	paste(x,y)	x/**\/y		/* instead of: x##y */
/* .fi
/*
/*	There is a good reason why the # and ## operators are not implemented
/*	in the unprototyper.
/*	After program text has gone through a non-ANSI C preprocessor, all
/*	information about the grouping of the operands of # and ## is lost.
/*	Thus, if the unprototyper were to perform these operations, it would
/*	produce correct results only in the most trivial cases. Operands
/*	with embedded blanks, operands that expand to null tokens, and nested
/*	use of # and/or ## would cause all kinds of obscure problems.
/* .PP
/*	Unsupported ANSI features:
/* .TP
/* trigraphs and #pragmas
/*	Trigraphs are useful only for systems with broken character sets.
/*	If the local compiler chokes on #pragma, insert a blank before the
/*	"#" character, and enclose the offending directive between #ifdef
/*	and #endif.
/* SEE ALSO
/* .ad
/* .fi
/*	cc(1), how to specify a non-default C preprocessor.
/*	Some versions of the lint(1) command are implemented as a shell
/*	script. It should require only minor modification for integration
/*	with the unprototyper. Other versions of the lint(1) command accept
/*	the same command syntax as the C compiler for the specification of a
/*	non-default preprocessor. Some research may be needed.
/* FILES
/*	/wherever/stdarg.h, provided with the unproto filter.
/* DIAGNOSTICS
/*	Problems are reported on the standard error stream.
/*	A non-zero exit status means that there was a problem.
/* BUGS
/*	The unprototyper should be run on preprocessed source only:
/*	unexpanded macros may confuse the program.
/*
/*	Declarations of (object) are misunderstood and will result in
/*	syntax errors: the objects between parentheses disappear.
/*
/*	Sometimes does not preserve whitespace after parentheses and commas.
/*	This is a purely aesthetical matter, and the compiler should not care.
/*	Whitespace within string constants is, of course, left intact.
/*
/*	Does not generate explicit type casts for function-argument
/*	expressions.  The lack of explicit conversions between integral
/*	and/or pointer argument types should not be a problem in environments
/*	where sizeof(int) == sizeof(long) == sizeof(pointer).  A more serious
/*	problem is the lack of automatic type conversions between integral and
/*	floating-point argument types.  Let lint(1) be your friend.
/* AUTHOR(S)
/*	Wietse Venema (wietse@wzv.win.tue.nl)
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	93/06/18 22:29:37
/* VERSION/RELEASE
/*	1.6
/*--*/

static char unproto_sccsid[] = "@(#) unproto.c 1.6 93/06/18 22:29:37";

/* C library */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>

extern void exit();
extern int optind;
extern char *optarg;
extern int getopt();

/* Application-specific stuff */

#include "vstring.h"
#include "stdarg.h"
#include "token.h"
#include "error.h"
#include "symbol.h"

/* Forward declarations. */

static struct token *dcl_flush();
static void block_flush();
static void block_dcls();
static struct token *show_func_ptr_type();
static struct token *show_struct_type();
static void show_arg_name();
static void show_type();
static void pair_flush();
static void check_cast();
static void show_empty_list();

#define	check_cast_flush(t)	(check_cast(t), tok_free(t))

#ifdef PIPE_THROUGH_CPP
static int pipe_stdin_through_cpp();
#endif

/* Disable debugging printfs while preserving side effects. */

#ifdef DEBUG
#define	DPRINTF	printf
#else
#define	DPRINTF (void)
#endif

/* An attempt to make some complicated expressions a bit more readable. */

#define	STREQ(x,y)		(*(x) == *(y) && !strcmp((x),(y)))

#define	LAST_ARG_AND_EQUAL(s,c)	((s)->next && (s)->next->next == 0 \
				&& (s)->head && ((s)->head == (s)->tail) \
				&& (STREQ((s)->head->vstr->str, (c))))

#define	LIST_BEGINS_WITH_STAR(s) (s->head->head && s->head->head->tokno == '*')

#define	IS_FUNC_PTR_TYPE(s)	(s->tokno == TOK_LIST && s->next \
				&& s->next->tokno == TOK_LIST \
				&& LIST_BEGINS_WITH_STAR(s))

/* What to look for to detect a (void) argument list. */

#ifdef MAP_VOID
#define	VOID_ARG	"int"		/* bare "void" is mapped to "int" */
#else
#define	VOID_ARG	"void"		/* bare "void" is left alone */
#endif

/* main - driver */

int     main(argc, argv)
int     argc;
char  **argv;
{
    register struct token *t;
#ifdef	PIPE_THROUGH_CPP			/* pipe through /lib/cpp */
    int     cpp_status;
    int     wait_pid;
    int     cpp_pid;

    cpp_pid = pipe_stdin_through_cpp(argv);
#endif

    sym_init();					/* prime the symbol table */

    while (t = tok_class()) {
	if (t = dcl_flush(t)) {			/* try declaration */
	    if (t->tokno == '{') {		/* examine rejected token */
		block_flush(t);			/* body */
	    } else {
		tok_flush(t);			/* other, recover */
	    }
	}
    }

#ifdef	PIPE_THROUGH_CPP			/* pipe through /lib/cpp */
    while ((wait_pid = wait(&cpp_status)) != -1 && wait_pid != cpp_pid)
	 /* void */ ;
    return (errcount != 0 || wait_pid != cpp_pid || cpp_status != 0);
#else
    return (errcount != 0);
#endif
}

#ifdef	PIPE_THROUGH_CPP		/* pipe through /lib/cpp */

/* pipe_stdin_through_cpp - avoid shell script overhead */

static int pipe_stdin_through_cpp(argv)
char  **argv;
{
    int     pipefds[2];
    int     pid;
    char  **cpptr = argv;
    int     i;
    struct stat st;

    /*
     * The code that sets up the pipe requires that file descriptors 0,1,2
     * are already open. All kinds of mysterious things will happen if that
     * is not the case. The following loops makes sure that descriptors 0,1,2
     * are set up properly. 
     */

    for (i = 0; i < 3; i++) {
	if (fstat(i, &st) == -1 && open("/dev/null", 2) != i) {
	    perror("open /dev/null");
	    exit(1);
	}
    }

    /*
     * With most UNIX implementations, the second non-option argument to
     * /lib/cpp specifies the output file. If an output file other than
     * stdout is specified, we must force /lib/cpp to write to stdout, and we
     * must redirect our own standard output to the specified output file.
     */

#define	IS_OPTION(cp) ((cp)[0] == '-' && (cp)[1] != 0)

    /* Skip to first non-option argument, if any. */

    while (*++cpptr && IS_OPTION(*cpptr))
	 /* void */ ;

    /*
     * Assume that the first non-option argument is the input file name. The
     * next argument could be the output destination or an option (System V
     * Release 2 /lib/cpp gets the options *after* the file arguments).
     */

    if (*cpptr && *++cpptr && **cpptr != '-') {

	/*
	 * The first non-option argument is followed by another argument that
	 * is not an option ("-stuff") or a hyphen ("-"). Redirect our own
	 * standard output before we clobber the file name.
	 */

	if (freopen(*cpptr, "w", stdout) == 0) {
	    perror(*cpptr);
	    exit(1);
	}
	/* Clobber the file name argument so that /lib/cpp writes to stdout */

	*cpptr = "-";
    }
    /* Set up the pipe that connects /lib/cpp to our standard input. */

    if (pipe(pipefds)) {
	perror("pipe");
	exit(1);
    }
    switch (pid = fork()) {
    case -1:					/* error */
	perror("fork");
	exit(1);
	/* NOTREACHED */
    case 0:					/* child */
	(void) close(pipefds[0]);		/* close reading end */
	(void) close(1);			/* connect stdout to pipe */
	if (dup(pipefds[1]) != 1)
	    fatal("dup() problem");
	(void) close(pipefds[1]);		/* close redundant fd */
	(void) execv(PIPE_THROUGH_CPP, argv);
	perror(PIPE_THROUGH_CPP);
	exit(1);
	/* NOTREACHED */
    default:					/* parent */
	(void) close(pipefds[1]);		/* close writing end */
	(void) close(0);			/* connect stdin to pipe */
	if (dup(pipefds[0]) != 0)
	    fatal("dup() problem");
	close(pipefds[0]);			/* close redundant fd */
	return (pid);
    }
}

#endif

/* show_arg_names - display function argument names */

static void show_arg_names(t)
register struct token *t;
{
    register struct token *s;

    /* Do argument names, but suppress void and rewrite trailing ... */

    if (LAST_ARG_AND_EQUAL(t->head, VOID_ARG)) {
	show_empty_list(t);			/* no arguments */
    } else {
	for (s = t->head; s; s = s->next) {	/* foreach argument... */
	    if (LAST_ARG_AND_EQUAL(s, "...")) {
#ifdef _VA_ALIST_				/* see ./stdarg.h */
		tok_show_ch(s);			/* ',' */
		put_str(_VA_ALIST_);		/* varargs magic */
#endif
	    } else {
		tok_show_ch(s);			/* '(' or ',' or ')' */
		show_arg_name(s);		/* extract argument name */
	    }
	}
    }
}

/* show_arg_types - display function argument types */

static void show_arg_types(t)
register struct token *t;
{
    register struct token *s;

    /* Do argument types, but suppress void and trailing ... */

    if (!LAST_ARG_AND_EQUAL(t->head, VOID_ARG)) {
	for (s = t->head; s; s = s->next) {	/* foreach argument... */
	    if (LAST_ARG_AND_EQUAL(s, "...")) {
#ifdef _VA_DCL_					/* see ./stdarg.h */
		put_str(_VA_DCL_);		/* varargs magic */
		put_nl();			/* make output look nicer */
#endif
	    } else {
		if (s->head != s->tail) {	/* really new-style argument? */
		    show_type(s);		/* rewrite type info */
		    put_ch(';');
		    put_nl();			/* make output look nicer */
		}
	    }
	}
    }
}

/* header_flush - rewrite new-style function heading to old style */

static void header_flush(t)
register struct token *t;
{
    show_arg_names(t);				/* show argument names */
    put_nl();					/* make output look nicer */
    show_arg_types(t);				/* show argument types */
    tok_free(t);				/* discard token */
}

/* fpf_header_names - define func returning ptr to func, no argument types */

static void fpf_header_names(list)
struct token *list;
{
    register struct token *s;
    register struct token *p;

    /*
     * Recurse until we find the argument list. Account for the rare case
     * that list is a comma-separated list (which should be a syntax error).
     * Display old-style fuction argument names.
     */

    for (s = list->head; s; s = s->next) {
	tok_show_ch(s);				/* '(' or ',' or ')' */
	for (p = s->head; p; p = p->next) {
	    if (p->tokno == TOK_LIST) {
		if (IS_FUNC_PTR_TYPE(p)) {	/* recurse */
		    fpf_header_names(p);
		    show_empty_list(p = p->next);
		} else {			/* display argument names */
		    show_arg_names(p);
		}
	    } else {				/* pass through other stuff */
		tok_show(p);
	    }
	}
    }
}

/* fpf_header_types - define func returning ptr to func, argument types only */

static void fpf_header_types(list)
struct token *list;
{
    register struct token *s;
    register struct token *p;

    /*
     * Recurse until we find the argument list. Account for the rare case
     * that list is a comma-separated list (which should be a syntax error).
     * Display old-style function argument types.
     */

    for (s = list->head; s; s = s->next) {
	for (p = s->head; p; p = p->next) {
	    if (p->tokno == TOK_LIST) {
		if (IS_FUNC_PTR_TYPE(p)) {	/* recurse */
		    fpf_header_types(p);
		    p = p->next;
		} else {			/* display argument types */
		    show_arg_types(p);
		}
	    }
	}
    }
}

/* fpf_header - define function returning pointer to function */

static void fpf_header(l1, l2)
struct token *l1;
struct token *l2;
{
    fpf_header_names(l1);			/* strip argument types */
    show_empty_list(l2);			/* strip prototype */
    put_nl();					/* nicer output */
    fpf_header_types(l1);			/* show argument types */
}

/* skip_enclosed - skip over enclosed tokens */

static struct token *skip_enclosed(p, stop)
register struct token *p;
register int stop;
{
    register int start = p->tokno;

    /* Always return a pointer to the last processed token, never NULL. */

    while (p->next) {
	p = p->next;
	if (p->tokno == start) {
	    p = skip_enclosed(p, stop);		/* recurse */
	} else if (p->tokno == stop) {
	    break;				/* done */
	}
    }
    return (p);
}

/* show_arg_name - extract argument name from argument type info */

static void show_arg_name(s)
register struct token *s;
{
    if (s->head) {
	register struct token *p;
	register struct token *t = 0;

	/* Find the last interesting item. */

	for (p = s->head; p; p = p->next) {
	    if (p->tokno == TOK_WORD) {
		t = p;				/* remember last word */
	    } else if (p->tokno == '{') {
		p = skip_enclosed(p, '}');	/* skip structured stuff */
	    } else if (p->tokno == '[') {
		break;				/* dimension may be a macro */
	    } else if (IS_FUNC_PTR_TYPE(p)) {
		t = p;				/* or function pointer */
		p = p->next;
	    }
	}

	/* Extract argument name from last interesting item. */

	if (t) {
	    if (t->tokno == TOK_LIST)
		show_arg_name(t->head);		/* function pointer, recurse */
	    else
		tok_show(t);			/* print last word */
	}
    }
}

/* show_type - rewrite type to old-style syntax */

static void show_type(s)
register struct token *s;
{
    register struct token *p;

    /*
     * Rewrite (*stuff)(args) to (*stuff)(). Rewrite word(args) to word(),
     * but only if the word was preceded by a word, '*' or '}'. Leave
     * anything else alone.
     */

    for (p = s->head; p; p = p->next) {
	if (IS_FUNC_PTR_TYPE(p)) {
	    p = show_func_ptr_type(p, p->next);	/* function pointer type */
	} else {
	    register struct token *q;
	    register struct token *r;

	    tok_show(p);			/* other */
	    if ((p->tokno == TOK_WORD || p->tokno == '*' || p->tokno == '}')
		&& (q = p->next) && q->tokno == TOK_WORD
		&& (r = q->next) && r->tokno == TOK_LIST) {
		tok_show(q);			/* show name */
		show_empty_list(p = r);		/* strip args */
	    }
	}
    }
}

/* show_func_ptr_type - display function_pointer type using old-style syntax */

static struct token *show_func_ptr_type(t1, t2)
struct token *t1;
struct token *t2;
{
    register struct token *s;

    /*
     * Rewrite (list1) (list2) to (list1) (). Account for the rare case that
     * (list1) is a comma-separated list. That should be an error, but we do
     * not want to waste any information.
     */

    for (s = t1->head; s; s = s->next) {
	tok_show_ch(s);				/* '(' or ',' or ')' */
	show_type(s);				/* recurse */
    }
    show_empty_list(t2);
    return (t2);
}

/* show_empty_list - display opening and closing parentheses (if available) */

static void show_empty_list(t)
register struct token *t;
{
    tok_show_ch(t->head);			/* opening paren */
    if (t->tail->tokno == ')')
	tok_show_ch(t->tail);			/* closing paren */
}

/* show_struct_type - display structured type, rewrite function-pointer types */

static struct token *show_struct_type(p)
register struct token *p;
{
    tok_show(p);				/* opening brace */

    while (p->next) {				/* XXX cannot return 0 */
	p = p->next;
	if (IS_FUNC_PTR_TYPE(p)) {
	    p = show_func_ptr_type(p, p->next);	/* function-pointer member */
	} else if (p->tokno == '{') {
	    p = show_struct_type(p);		/* recurse */
	} else {
	    tok_show(p);			/* other */
	    if (p->tokno == '}') {
		return (p);			/* done */
	    }
	}
    }
    DPRINTF("/* missing '}' */");
    return (p);
}

/* is_func_ptr_cast - recognize function-pointer type cast */

static int is_func_ptr_cast(t)
register struct token *t;
{
    register struct token *p;

    /*
     * Examine superficial structure. Require (list1) (list2). Require that
     * list1 begins with a star.
     */

    if (!IS_FUNC_PTR_TYPE(t))
	return (0);

    /*
     * Make sure that there is no name in (list1). Do not worry about
     * unexpected tokens, because the compiler will complain anyway.
     */

    for (p = t->head->head; p; p = p->next) {
	switch (p->tokno) {
	case TOK_LIST:				/* recurse */
	    return (is_func_ptr_cast(p));
	case TOK_WORD:				/* name in list */
	    return (0);
	case '[':
	    return (1);				/* dimension may be a macro */
	}
    }
    return (1);					/* no name found */
}

/* check_cast - display ()-delimited, comma-separated list */

static void check_cast(t)
struct token *t;
{
    register struct token *s;
    register struct token *p;

    /*
     * Rewrite function-pointer types and function-pointer casts. Do not
     * blindly rewrite (*list1)(list2) to (*list1)(). Function argument lists
     * are about the only thing we can discard without provoking diagnostics
     * from the compiler.
     */

    for (s = t->head; s; s = s->next) {
	tok_show_ch(s);				/* '(' or ',' or ')' */
	for (p = s->head; p; p = p->next) {
	    switch (p->tokno) {
	    case TOK_LIST:
		if (is_func_ptr_cast(p)) {	/* not: IS_FUNC_PTR_TYPE(p) */
		    p = show_func_ptr_type(p, p->next);
		} else {
		    check_cast(p);		/* recurse */
		}
		break;
	    case '{':
		p = show_struct_type(p);	/* rewrite func. ptr. types */
		break;
	    default:
		tok_show(p);
		break;
	    }
	}
    }
}

/* block_dcls - on the fly rewrite decls/initializers at start of block */

static void block_dcls()
{
    register struct token *t;

    /*
     * Away from the top level, a declaration should be preceded by type or
     * storage-class information. That is why inside blocks, structs and
     * unions we insist on reading one word before passing the _next_ token
     * to the dcl_flush() function.
     * 
     * Struct and union declarations look the same everywhere: we make an
     * exception for these more regular constructs and pass the "struct" and
     * "union" tokens to the type_dcl() function.
     */

    while (t = tok_class()) {
	switch (t->tokno) {
	case TOK_WSPACE:			/* preserve white space */
	case '\n':				/* preserve line count */
	    tok_flush(t);
	    break;
	case TOK_WORD:				/* type declarations? */
	    tok_flush(t);			/* advance to next token */
	    t = tok_class();			/* null return is ok */
	    /* FALLTRHOUGH */
	case TOK_COMPOSITE:			/* struct or union */
	    if ((t = dcl_flush(t)) == 0)
		break;
	    /* FALLTRHOUGH */
	default:				/* end of declarations */
	    DPRINTF("/* end dcls */");
	    /* FALLTRHOUGH */
	case '}':				/* end of block */
	    tok_unget(t);
	    return;
	}
    }
}

/* block_flush - rewrite struct, union or statement block on the fly */

static void block_flush(t)
register struct token *t;
{
    static int count = 0;

    tok_flush(t);
    DPRINTF("/*%d*/", ++count);

    /*
     * Rewrite function pointer types in declarations and function pointer
     * casts in initializers at start of block.
     */

    block_dcls();

    /* Remainder of block: only rewrite function pointer casts. */

    while (t = tok_class()) {
	if (t->tokno == TOK_LIST) {
	    check_cast_flush(t);
	} else if (t->tokno == '{') {
	    block_flush(t);
	} else {
	    tok_flush(t);
	    if (t->tokno == '}') {
		DPRINTF("/*%d*/", count--);
		return;
	    }
	}
    }
    DPRINTF("/* missing '}' */");
}

/* pair_flush - on the fly rewrite casts in grouped stuff */

static void pair_flush(t, start, stop)
register struct token *t;
register int start;
register int stop;
{
    tok_flush(t);

    while (t = tok_class()) {
	if (t->tokno == start) {		/* recurse */
	    pair_flush(t, start, stop);
	} else if (t->tokno == TOK_LIST) {	/* expression or cast */
	    check_cast_flush(t);
	} else {				/* other, copy */
	    tok_flush(t);
	    if (t->tokno == stop) {		/* done */
		return;
	    }
	}
    }
    DPRINTF("/* missing '%c' */", stop);
}

/* initializer - on the fly rewrite casts in initializer */

static void initializer()
{
    register struct token *t;

    while (t = tok_class()) {
	switch (t->tokno) {
	case ',':				/* list separator */
	case ';':				/* list terminator */
	    tok_unget(t);
	    return;
	case TOK_LIST:				/* expression or cast */
	    check_cast_flush(t);
	    break;
	case '[':				/* array subscript, may nest */
	    pair_flush(t, '[', ']');
	    break;
	case '{':				/* structured data, may nest */
	    pair_flush(t, '{', '}');
	    break;
	default:				/* other, just copy */
	    tok_flush(t);
	    break;
	}
    }
}

/* func_ptr_dcl_flush - rewrite function pointer stuff */

static struct token *func_ptr_dcl_flush(list)
register struct token *list;
{
    register struct token *t;
    register struct token *t2;

    /*
     * Ignore blanks and newlines because we are too lazy to maintain more
     * than one token worth of lookahead. The output routines will regenerate
     * discarded newline tokens.
     */

    while (t = tok_class()) {
	switch (t->tokno) {
	case TOK_WSPACE:
	case '\n':
	    tok_free(t);
	    break;
	case TOK_LIST:
	    /* Function pointer or function returning pointer to function. */
	    while ((t2 = tok_class())		/* skip blanks etc. */
		   &&(t2->tokno == TOK_WSPACE || t2->tokno == '\n'))
		tok_free(t2);
	    switch (t2 ? t2->tokno : 0) {
	    case '{':				/* function heading (new) */
		fpf_header(list, t);
		break;
	    case TOK_WORD:			/* function heading (old) */
		tok_show(list);
		tok_show(t);
		break;
	    default:				/* func pointer type */
		(void) show_func_ptr_type(list, t);
		break;
	    }
	    tok_free(list);
	    tok_free(t);
	    if (t2)
		tok_unget(t2);
	    return (0);
	default:				/* not a declaration */
	    tok_unget(t);
	    return (list);
	}
    }

    /* Hit EOF; must be mistake, but do not waste any information. */

    return (list);
}

/* function_dcl_flush - rewrite function { heading, type declaration } */

static struct token *function_dcl_flush(list)
register struct token *list;
{
    register struct token *t;

    /*
     * Ignore blanks and newlines because we are too lazy to maintain more
     * than one token worth of lookahead. The output routines will regenerate
     * ignored newline tokens.
     */

    while (t = tok_class()) {
	switch (t->tokno) {
	case TOK_WSPACE:
	case '\n':
	    tok_free(t);
	    break;
	case '{':
	    /* Function heading: word (list) { -> old style heading */
	    header_flush(list);
	    tok_unget(t);
	    return (0);
	case TOK_WORD:
	    /* Old-style function heading: word (list) word... */
	    tok_flush(list);
	    tok_unget(t);
	    return (0);
	case TOK_LIST:
	    /* Function pointer: word (list1) (list2) -> word (list1) () */
	    tok_flush(list);
	    show_empty_list(t);
	    tok_free(t);
	    return (0);
	case ',':
	case ';':
	    /* Function type declaration: word (list) -> word () */
	    show_empty_list(list);
	    tok_free(list);
	    tok_unget(t);
	    return (0);
	default:
	    /* Something else, reject the list. */
	    tok_unget(t);
	    return (list);
	}
    }

    /* Hit EOF; must be mistake, but do not waste any information. */

    return (list);
}

/* dcl_flush - parse declaration on the fly, return rejected token */

static struct token *dcl_flush(t)
register struct token *t;
{
    register int got_word;

    /*
     * Away from the top level, type or storage-class information is required
     * for an (extern or forward) function type declaration or a variable
     * declaration.
     * 
     * With our naive word-counting approach, this means that the caller should
     * read one word before passing the next token to us. This is how we
     * distinguish, for example, function declarations from function calls.
     * 
     * An exception are structs and unions, because they look the same at any
     * level. The caller should give is the "struct" or "union" token.
     */

    for (got_word = 0; t; t = tok_class()) {
	switch (t->tokno) {
	case TOK_WSPACE:			/* advance past blanks */
	case '\n':				/* advance past newline */
	case '*':				/* indirection: keep trying */
	    tok_flush(t);
	    break;
	case TOK_WORD:				/* word: keep trying */
	case TOK_COMPOSITE:			/* struct or union */
	    got_word = 1;
	    tok_flush(t);
	    break;
	default:

	    /*
	     * Function pointer types can be preceded by zero or more words
	     * (at least one when not at the top level). Other stuff can be
	     * accepted only after we have seen at least one word (two words
	     * when not at the top level). See also the above comment on
	     * structs and unions.
	     */

	    if (t->tokno == TOK_LIST && LIST_BEGINS_WITH_STAR(t)) {
		if (t = func_ptr_dcl_flush(t)) {
		    return (t);			/* reject token */
		} else {
		    got_word = 1;		/* for = and [ and , and ; */
		}
	    } else if (got_word == 0) {
		return (t);			/* reject token */
	    } else {
		switch (t->tokno) {
		case TOK_LIST:			/* function type */
		    if (t = function_dcl_flush(t))
			return (t);		/* reject token */
		    break;
		case '[':			/* dimension, does not nest */
		    pair_flush(t, '[', ']');
		    break;
		case '=':			/* initializer follows */
		    tok_flush(t);
		    initializer();		/* rewrite casts */
		    break;
		case '{':			/* struct, union, may nest */
		    block_flush(t);		/* use code for stmt blocks */
		    break;
		case ',':			/* separator: keep trying */
		    got_word = 0;
		    tok_flush(t);
		    break;
		case ';':			/* terminator: succeed */
		    tok_flush(t);
		    return (0);
		default:			/* reject token */
		    return (t);
		}
	    }
	}
    }
    return (0);					/* hit EOF */
}

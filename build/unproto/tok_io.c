/*++
/* NAME
/*	tok_io 3
/* SUMMARY
/*	token I/O
/* PACKAGE
/*	unproto
/* SYNOPSIS
/*	#include "token.h"
/*
/*	struct token *tok_get()
/*
/*	void tok_flush(t)
/*	struct token *t;
/*
/*	void tok_show(t)
/*	struct token *t;
/*
/*	void tok_show_ch(t)
/*	struct token *t;
/*
/*	void put_str(s)
/*	char *s;
/*
/*	void put_ch(c)
/*	int c;
/*
/*	void put_nl()
/*
/*	char *in_path;
/*	int in_line;
/* DESCRIPTION
/*	These functions read from stdin and write to stdout. The
/*	tokenizer keeps track of where the token appeared in the input
/*	stream; on output, this information is used to preserve correct
/*	line number information (even after lots of token lookahead or
/*	after function-header rewriting) so that diagnostics from the
/*	next compiler stage make sense.
/*
/*	tok_get() reads the next token from standard input. It returns
/*	a null pointer when the end of input is reached.
/*
/*	tok_show() displays the contents of a (possibly composite) token
/*	on the standard output.
/*
/*	tok_show_ch() displays the contents of a single-character token
/*	on the standard output. The character should not be a newline.
/*
/*	tok_flush() displays the contents of a (possibly composite) token
/*	on the standard output and makes it available for re-use.
/*
/*	put_str() writes a null-terminated string to standard output.
/*	There should be no newline characters in the string argument.
/*
/*	put_ch() writes one character to standard output. The character
/*	should not be a newline.
/*
/*	put_nl() outputs a newline character and adjusts the program's idea of
/*	the current output line.
/*
/*	The in_path and in_line variables contain the file name and
/*	line number of the most recently read token.
/* BUGS
/*	The tokenizer is just good enough for the unproto filter.
/*	As a benefit, it is quite fast.
/* AUTHOR(S)
/*	Wietse Venema
/*	Eindhoven University of Technology
/*	Department of Mathematics and Computer Science
/*	Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands
/* LAST MODIFICATION
/*	92/01/15 21:52:59
/* VERSION/RELEASE
/*	1.3
/*--*/

static char io_sccsid[] = "@(#) tok_io.c 1.3 92/01/15 21:52:59";

/* C library */

#include <stdio.h>
#include <ctype.h>

extern char *strchr();
extern char *malloc();
extern char *realloc();
extern char *strcpy();

/* Application-specific stuff */

#include "token.h"
#include "vstring.h"
#include "error.h"

extern char *strsave();			/* XXX need include file */

/* Stuff to keep track of original source file name and position */

static char def_path[] = "";		/* default path name */

char   *in_path = def_path;		/* current input file name */
int     in_line = 1;			/* current input line number */

static char *out_path = def_path;	/* last name in output line control */
static int out_line = 1;		/* current output line number */
int     last_ch;			/* type of last output */

/* Forward declarations */

static int read_quoted();
static void read_comment();
static int backslash_newline();
static char *read_hex();
static char *read_octal();
static void fix_line_control();

 /*
  * Character input with one level of pushback. The INPUT() macro recursively
  * strips backslash-newline pairs from the input stream. The UNPUT() macro
  * should be used only for characters obtained through the INPUT() macro.
  * 
  * After skipping a backslash-newline pair, the input line counter is not
  * updated, and we continue with the same logical source line. We just
  * update a counter with the number of backslash-newline sequences that must
  * be accounted for (backslash_newline() updates the counter). At the end of
  * the logical source line, an appropriate number of newline characters is
  * pushed back (in tok_get()). I do not know how GCC handles this, but it
  * seems to produce te same output.
  * 
  * Because backslash_newline() recursively calls itself (through the INPUT()
  * macro), we will run out of stack space, given a sufficiently long
  * sequence of backslash-newline pairs.
  */

static char in_char = 0;		/* push-back storage */
static int in_flag = 0;			/* pushback available */
static int nl_compensate = 0;		/* line continuation kluge */

#define INPUT(c) (in_flag ? (in_flag = 0, c = in_char) : \
		    (c = getchar()) != '\\' ? c : \
		    (c = getchar()) != '\n' ? (ungetc(c, stdin), c = '\\') : \
		    (c = backslash_newline()))
#define	UNPUT(c) (in_flag = 1, in_char = c)

/* Directives that should be ignored. */

#ifdef IGNORE_DIRECTIVES

static char *ignore_directives[] = {
    IGNORE_DIRECTIVES,
    0,
};

#endif

/* Modified string and ctype stuff. */

#define	STREQUAL(x,y)	(*(x) == *(y) && strcmp((x),(y)) == 0)

#define	ISALNUM(c)	(isalnum(c) || (c) == '_')
#define	ISALPHA(c)	(isalpha(c) || (c) == '_')
#define	ISSPACE(c)	(isspace(c) && c != '\n')
#define	ISDOT(c)	(c == '.')
#define	ISHEX(c)	(isdigit(c) || strchr("abcdefABCDEF", c) != 0)
#define	ISOCTAL(c)	(isdigit(c) && (c) != '8' && (c) != '9')

/* Collect all characters that satisfy one condition */

#define	COLLECT(v,c,cond) { \
				register struct vstring *vs = v; \
				register char *cp = vs->str; \
				*cp++ = c; \
				while (INPUT(c) != EOF) { \
				    if (cond) { \
					if (VS_ADDCH(vs, cp, c) == 0) \
					    fatal("out of memory"); \
				    } else { \
					UNPUT(c); \
					break; \
				    } \
				} \
				*cp = 0; \
			    }

/* Ensure that output line information is correct */

#define	CHECK_LINE_CONTROL(p,l) { if (out_path != (p) || out_line != (l)) \
					fix_line_control((p),(l)); }

/* do_control - parse control line */

static int do_control()
{
    struct token *t;
    int     line;
    char   *path;

    /* Make sure that the directive shows up in the right place. */

    CHECK_LINE_CONTROL(in_path, in_line);

    while (t = tok_get()) {
	switch (t->tokno) {

	case TOK_WSPACE:
	    /* Ignore blanks after "#" token. */
	    tok_free(t);
	    break;

	case TOK_NUMBER:

	    /*
	     * Line control is of the form: number pathname junk. Since we
	     * have no idea what junk the preprocessor may generate, we copy
	     * all line control tokens to stdout.
	     */

	    put_str("# ");
	    line = atoi(t->vstr->str);		/* extract line number */
	    tok_flush(t);
	    while ((t = tok_get()) && t->tokno == TOK_WSPACE)
		tok_flush(t);			/* copy white space */
	    if (t) {				/* extract path name */
		path = (t->tokno == '"') ? strsave(t->vstr->str) : in_path;
		do {
		    tok_flush(t);		/* copy until newline */
		} while (t->tokno != '\n' && (t = tok_get()));
	    }
	    out_line = in_line = line;		/* synchronize */
	    out_path = in_path = path;		/* synchronize */
	    return;

#ifdef IGNORE_DIRECTIVES

	case TOK_WORD:

	    /*
	     * Optionally ignore other #directives. This is only a partial
	     * solution, because the preprocessor will still see them.
	     */
	    {
		char  **cpp;
		char   *cp = t->vstr->str;

		for (cpp = ignore_directives; *cpp; cpp++) {
		    if (STREQUAL(cp, *cpp)) {
			do {
			    tok_free(t);
			} while (t->tokno != '\n' && (t = tok_get()));
			return;
		    }
		}
	    }
	    /* FALLTHROUGH */
#endif
	default:
	    /* Pass through. */
	    put_ch('#');
	    do {
		tok_flush(t);
	    } while (t->tokno != '\n' && (t = tok_get()));
	    return;

	case 0:
	    /* Hit EOF, punt. */
	    put_ch('#');
	    return;
	}
    }
}

/* backslash_newline - fix up things after reading a backslash-newline pair */

static int backslash_newline()
{
    register int c;

    nl_compensate++;
    return (INPUT(c));
}

/* tok_get - get next token */

static int last_tokno = '\n';

struct token *tok_get()
{
    register struct token *t;
    register int c;
    int     d;

    /*
     * Get one from the pool and fill it in. The loop is here in case we hit
     * a preprocessor control line, which happens in a minority of all cases.
     * We update the token input path and line info *after* backslash-newline
     * processing or the newline compensation would go wrong.
     */

    t = tok_alloc();

    for (;;) {
	if ((INPUT(c)) == EOF) {
	    tok_free(t);
	    return (0);
	} else if ((t->line = in_line, t->path = in_path), !isascii(c)) {
	    t->vstr->str[0] = c;
	    t->vstr->str[1] = 0;
	    t->tokno = TOK_OTHER;
	    break;
	} else if (ISSPACE(c)) {
	    COLLECT(t->vstr, c, ISSPACE(c));
	    t->tokno = TOK_WSPACE;
	    break;
	} else if (ISALPHA(c)) {
	    COLLECT(t->vstr, c, ISALNUM(c));
	    t->tokno = TOK_WORD;
	    break;
	} else if (isdigit(c)) {
	    COLLECT(t->vstr, c, isdigit(c));
	    t->tokno = TOK_NUMBER;
	    break;
	} else if (c == '"' || c == '\'') {
	    t->tokno = read_quoted(t->vstr, c);	/* detect missing end quote */
	    break;
	} else if (ISDOT(c)) {
	    COLLECT(t->vstr, c, ISDOT(c));
	    t->tokno = TOK_OTHER;
	    break;
	} else if (c == '#' && last_tokno == '\n') {
	    do_control();
	    continue;
	} else {
	    t->vstr->str[0] = c;
	    if (c == '\n') {
		in_line++;
		if (nl_compensate > 0) {	/* compensation for bs-nl */
		    UNPUT('\n');
		    nl_compensate--;
		}
	    } else if (c == '/') {
		if ((INPUT(d)) == '*') {
		    t->vstr->str[1] = d;	/* comment */
		    read_comment(t->vstr);
		    t->tokno = TOK_WSPACE;
		    break;
		} else {
		    if (d != EOF)
			UNPUT(d);
		}
	    } else if (c == '\\') {
		t->vstr->str[1] = (INPUT(c) == EOF ? 0 : c);
		t->vstr->str[2] = 0;
		t->tokno = TOK_OTHER;
		break;
	    }
	    t->vstr->str[1] = 0;
	    t->tokno = c;
	    break;
	}
    }
    last_tokno = t->tokno;
    t->end_line = in_line;
    return (t);
}

/* read_quoted - read string or character literal, canonicalize escapes */

static int read_quoted(vs, ch)
register struct vstring *vs;
int     ch;
{
    register char *cp = vs->str;
    register int c;
    int     ret = TOK_OTHER;

    *cp++ = ch;

    /*
     * Clobber the token type in case of a premature newline or EOF. This
     * prevents us from attempting to concatenate string constants with
     * broken ones that have no closing quote.
     */

    while (INPUT(c) != EOF) {
	if (c == '\n') {			/* newline in string */
	    UNPUT(c);
	    break;
	}
	if (VS_ADDCH(vs, cp, c) == 0)		/* store character */
	    fatal("out of memory");
	if (c == ch) {				/* closing quote */
	    ret = c;
	    break;
	}
	if (c == '\\') {			/* parse escape sequence */
	    if ((INPUT(c)) == EOF) {		/* EOF, punt */
		break;
	    } else if (c == 'a') {		/* \a -> audible bell */
		if ((cp = vs_strcpy(vs, cp, BELL)) == 0)
		    fatal("out of memory");
	    } else if (c == 'x') {		/* \xhh -> \nnn */
		cp = read_hex(vs, cp);
	    } else if (ISOCTAL(c) && ch != '\'') {
		cp = read_octal(vs, cp, c);	/* canonicalize \octal */
	    } else {
		if (VS_ADDCH(vs, cp, c) == 0)	/* \other: leave alone */
		    fatal("out of memory");
	    }
	}
    }
    *cp = 0;
    return (ret);
}

/* read_comment - stuff a whole comment into one huge token */

static void read_comment(vs)
register struct vstring *vs;
{
    register char *cp = vs->str + 2;	/* skip slash star */
    register int c;
    register int d;

    while (INPUT(c) != EOF) {
	if (VS_ADDCH(vs, cp, c) == 0)
	    fatal("out of memory");
	if (c == '*') {
	    if ((INPUT(d)) == '/') {
		if (VS_ADDCH(vs, cp, d) == 0)
		    fatal("out of memory");
		break;
	    } else {
		if (d != EOF)
		    UNPUT(d);
	    }
	} else if (c == '\n') {
	    in_line++;
	} else if (c == '\\') {
	    if ((INPUT(d)) != EOF && VS_ADDCH(vs, cp, d) == 0)
		fatal("out of memory");
	}
    }
    *cp = 0;
}

/* read_hex - rewrite hex escape to three-digit octal escape */

static char *read_hex(vs, cp)
struct vstring *vs;
register char *cp;
{
    register int c;
    register int i;
    char    buf[BUFSIZ];
    int     len;
    unsigned val;

    /*
     * Eat up all subsequent hex digits. Complain later when there are too
     * many.
     */

    for (i = 0; i < sizeof(buf) && (INPUT(c) != EOF) && ISHEX(c); i++)
	buf[i] = c;
    buf[i] = 0;

    if (i < sizeof(buf) && c)
	UNPUT(c);

    /*
     * Convert hex form to three-digit octal form. The three-digit form is
     * used so that strings can be concatenated without problems. Complain
     * about malformed input; truncate the result to at most three octal
     * digits.
     */

    if (i == 0) {
	error("\\x escape sequence without hexadecimal digits");
	if (VS_ADDCH(vs, cp, 'x') == 0)
	    fatal("out of memory");
    } else {
	(void) sscanf(buf, "%x", &val);
	sprintf(buf, "%03o", val);
	if ((len = strlen(buf)) > 3)
	    error("\\x escape sequence yields non-character value");
	if ((cp = vs_strcpy(vs, cp, buf + len - 3)) == 0)
	    fatal("out of memory");
    }
    return (cp);
}

/* read_octal - convert octal escape to three-digit format */

static char obuf[] = "00123";

static char *read_octal(vs, cp, c)
register struct vstring *vs;
register char *cp;
register int c;
{
    register int i;

#define	buf_input (obuf + 2)

    /* Eat up at most three octal digits. */

    buf_input[0] = c;
    for (i = 1; i < 3 && (INPUT(c) != EOF) && ISOCTAL(c); i++)
	buf_input[i] = c;
    buf_input[i] = 0;

    if (i < 3 && c)
	UNPUT(c);

    /*
     * Leave three-digit octal escapes alone. Convert one-digit and two-digit
     * octal escapes to three-digit form by prefixing them with a suitable
     * number of '0' characters. This is done so that strings can be
     * concatenated without problems.
     */

    if ((cp = vs_strcpy(vs, cp, buf_input + i - 3)) == 0)
	fatal("out of memory");
    return (cp);
}

/* put_nl - emit newline and adjust output line count */

void    put_nl()
{
    put_ch('\n');
    out_line++;
}

/* fix_line_control - to adjust path and/or line count info in output */

static void fix_line_control(path, line)
register char *path;
register int line;
{

    /*
     * This function is called sporadically, so it should not be a problem
     * that we repeat some of the tests that preceded this function call.
     * 
     * Emit a newline if we are not at the start of a line.
     * 
     * If we switch files, or if we jump backwards, emit line control. If we
     * jump forward, emit the proper number of newlines to compensate.
     */

    if (last_ch != '\n')			/* terminate open line */
	put_nl();
    if (path != out_path || line < out_line) {	/* file switch or back jump */
	printf("# %d %s\n", out_line = line, out_path = path);
	last_ch = '\n';
    } else {					/* forward jump */
	while (line > out_line)
	    put_nl();
    }
}

/* tok_show_ch - output single-character token (not newline) */

void    tok_show_ch(t)
register struct token *t;
{
    CHECK_LINE_CONTROL(t->path, t->line);

    put_ch(t->tokno);				/* show token contents */
}

/* tok_show - output (possibly composite) token */

void    tok_show(t)
register struct token *t;
{
    register struct token *p;

    if (t->tokno == TOK_LIST) {
	register struct token *s;

	/*
	 * This branch is completely in terms of tok_xxx() primitives, so
	 * there is no need to check the line control information.
	 */

	for (s = t->head; s; s = s->next) {
	    tok_show_ch(s);			/* '(' or ',' or ')' */
	    for (p = s->head; p; p = p->next)
		tok_show(p);			/* show list element */
	}
    } else {
	register char *cp = t->vstr->str;

	/*
	 * Measurements show that it pays off to give special treatment to
	 * single-character tokens. Note that both types of token may cause a
	 * change of output line number.
	 */

	CHECK_LINE_CONTROL(t->path, t->line);
	if (cp[1] == 0) {
	    put_ch(*cp);			/* single-character token */
	} else {
	    put_str(cp);			/* multi_character token */
	}
	out_line = t->end_line;			/* may span multiple lines */
	for (p = t->head; p; p = p->next)
	    tok_show(p);			/* trailing blanks */
    }
}

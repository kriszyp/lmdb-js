/* @(#) token.h 1.4 92/01/15 21:53:17 */

struct token {
    int     tokno;			/* token value, see below */
    char   *path;			/* file name */
    int     line;			/* line number at token start */
    int     end_line;			/* line number at token end */
    struct vstring *vstr;		/* token contents */
    struct token *next;
    struct token *head;
    struct token *tail;
};

/* Special token values */

#define	TOK_LIST	256		/* () delimited list */
#define	TOK_WORD	257		/* keyword or identifier */
#define	TOK_NUMBER	258		/* one or more digits */
#define	TOK_WSPACE	259		/* comment, white space, not newline */
#define	TOK_OTHER	260		/* other token */
#define	TOK_CONTROL	261		/* flow control keyword */
#define	TOK_COMPOSITE	262		/* struct or union keyword */
#define	TOK_DATE	263		/* date: Mmm dd yyyy */
#define	TOK_TIME	264		/* time: hh:mm:ss */
#define	TOK_VOID	265		/* void keyword */

/* Input/output functions and macros */

extern struct token *tok_get();		/* read next single token */
extern void tok_show();			/* display (composite) token */
extern struct token *tok_class();	/* classify tokens */
extern void tok_unget();		/* stuff token back into input */
extern void put_nl();			/* print newline character */
extern void tok_show_ch();		/* emit single-character token */

#define	tok_flush(t)	(tok_show(t), tok_free(t))

#ifdef DEBUG
#define put_ch(c)	(putchar(last_ch = c),fflush(stdout))
#define put_str(s)	(fputs(s,stdout),last_ch = 0,fflush(stdout))
#else
#define put_ch(c)	putchar(last_ch = c)
#define put_str(s)	(fputs(s,stdout),last_ch = 0)
#endif

/* Memory management */

struct token *tok_alloc();		/* allocate token storage */
extern void tok_free();			/* re-cycle storage */

/* Context */

extern char *in_path;			/* current input path name */
extern int in_line;			/* current input line number */
extern int last_ch;			/* type of last output */

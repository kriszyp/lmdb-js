/* @(#) symbol.h 1.1 91/09/22 21:21:42 */

struct symbol {
    char   *name;			/* symbol name */
    int     type;			/* symbol type */
    struct symbol *next;
};

extern void sym_enter();		/* add symbol to table */
extern struct symbol *sym_find();	/* locate symbol */
extern void sym_init();			/* prime the table */

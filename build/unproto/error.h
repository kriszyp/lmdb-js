/* @(#) error.h 1.2 92/01/15 21:53:14 */

extern int errcount;			/* error counter */
extern void error();			/* default context */
extern void error_where();		/* user-specified context */
extern void fatal();			/* fatal error */

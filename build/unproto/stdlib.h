/* @(#) stdlib.h 1.1 92/02/15 17:25:45 */

#ifndef _stdlib_h_
#define _stdlib_h_

/* NULL is also defined in <stdio.h> */

#ifndef NULL
#define NULL	0
#endif

/*
 * Some functions in this file will be missing from the typical pre-ANSI
 * UNIX library. Some pre-ANSI UNIX library functions have return types
 * that differ from what ANSI requires.
 */

extern double atof();
extern int atoi();
extern long atol();
extern double strtod();
extern long strtol();
extern unsigned long strtoul();
extern int rand();
extern void srand();
extern char *calloc();
extern char *malloc();
extern char *realloc();
extern void free();
extern void abort();
extern void exit();
extern int atextit();
extern int system();
extern char *getenv();
extern char *bsearch();
extern void qsort();
extern int abs();
extern long labs();

typedef struct {
    int     quot;
    int     rem;
} div_t;

typedef struct {
    long    quot;
    long    rem;
} ldiv_t;

extern div_t div();
extern ldiv_t ldiv();

#endif /* _stdlib_h_ */

#include <stdio.h>
#include <ac/ctype.h>
#include <ac/string.h>
extern char *strdup (const char *);

/* in faxtotpc.c */
void  strip_nonnum ( char *str );
char *remove_parens( char *ibuf, char *obuf );
char *munge_phone  ( char *ibuf, char *obuf );
char *faxtotpc     ( char *phone, char *userinfo );

/* $OpenLDAP$ */
#ifndef FAX500_H
#define FAX500_H 1

/* in faxtotpc.c */
void  strip_nonnum ( char *str );
char *remove_parens( char *ibuf, char *obuf );
char *munge_phone  ( char *ibuf, char *obuf );
char *faxtotpc     ( char *phone, char *userinfo );

#endif

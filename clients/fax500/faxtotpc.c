/* $OpenLDAP$ */
/*
 * Copyright (c) 1993 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 *
 * Routines for parsing the facsimileTelephoneNumber field out of
 * an X.500 entry and converting it to a "tpc.int" domain name.
 *
 * char *faxtotpc( char *str, char *userinfo)
 *
 * faxtotpc() returns a pointer to a string allocated with malloc(3).
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "fax500.h"

#define	TPCDOMAIN	"tpc.int"

/*
 * Remove everything from 'str' which is not a digit
 */
void
strip_nonnum( char *str )
{
	char *p, *q;
	p = q = str;
	for (;;) {
		if (*p == '\0') {
			*q = *p;
			return;
		}

		if (isdigit((u_char) *p)) {
			*q = *p;
			p++;
			q++;
		} else {
			p++;
		}
	}
}



/* 
 * Remove anything of the form (blah) where
 * "blah" contains a non-numeric character.
 */
char *
remove_parens( char *ibuf, char *obuf )
{
	char *p = ibuf;
	char *q = obuf;

	while (*p != '\0') {
		char *s;
		char *t;
		if (*p == '(') {
			/* look for a closing paren */
			if (( s = strchr(p, ')')) != NULL) {
				/* Check the string between p and s */
				/* for non-numeric characters       */
				t = p + 1;
				while (t < s) {
					if (!isdigit((u_char) *t)) {
						/* garbage, delete */
						p = s + 1;
						t = p;
						break;
					}
					t++;
				}
				/* when we get here, p points to the first */
				/* thing we want to keep, t to the last.   */
				strncpy(q, p,  t - p);
				q += t - p;
				p = t;
			} else {
				/* no closing paren, what to do?  keep it */
				*q = *p;
				p++;
				q++;
			}
		} else {
			/* not a paren - copy out */
			*q = *p;
			p++;
			q++;
		}
	}
	*q = '\0';	/* terminate output string */
	return(obuf);
}




/*
 * Apply local fixups to phone numbers here.  Replace this routine
 * with code to expand common "abbreviations" for phone numbers.  For
 * example, on the U-M campus, it's only necessary to dial the last
 * 5 digits of the telephone number, and hence people here tend to
 * give only the last 5 digits of their fax numbers.
 *
 * Local U-M mods:
 * If exactly 5 digits were provided, assume it's a campus
 * phone number and prepend "1313nm" where "mn" are computed
 * according to the following:
 * first digit of 
 * 5-digit "Local" 
 * phone              mn
 * -----              --
 * 3                  76 e.g. "31234" -> "7631234"
 * 4                  76
 * 7                  74
 * 6                  93
 * 8                  99
 */
char *
munge_phone( char *ibuf, char *obuf )
{
#define	UMAREACODE	"1313"

	char prefix[3];

	if (strlen(ibuf) == 7) {
		/* Assume local number w/o area code */
		sprintf(obuf, "%s%s", UMAREACODE, ibuf);
		return(obuf);
	}
	if (strlen(ibuf) == 10) {
		/* Assume local number with area code */
		sprintf(obuf, "%s%s", "1", ibuf);
		return(obuf);
	}
	if (strlen(ibuf) != 5) {
		/* Not 5 digits - leave alone */
		strcpy(obuf, ibuf);
		return(obuf);
	}

	switch (ibuf[0]) {
	  case '3'	:
	  case '4'	:	strcpy(prefix, "76");
				break;
	  case '7'	:	strcpy(prefix, "74");
				break;
	  case '6'	:	strcpy(prefix, "93");
				break;
	  case '8'	:	strcpy(prefix, "99");
				break;
	  default	:	/* Unknown, leave alone */
				strcpy(obuf, ibuf);
				return(obuf);
	}
	sprintf(obuf, "%s%s%s", UMAREACODE, prefix, ibuf);
	return(obuf);
}



/* 
 * Convert string to "tpc.int" domain name.
 */
char *
faxtotpc( char *phone, char *userinfo )
{
	char *p;
	char *q;
	char ibuf[255];
	char obuf[255];

	/* nuke spaces */
	strcpy(ibuf, phone);
	for (p = ibuf, q = obuf; *p != '\0'; p++) {
		if (*p != ' ') {
			*q = *p;
			q++;
		}
	}
	*q = '\0';
	strcpy(ibuf, obuf);

	remove_parens(ibuf, obuf);
	strcpy(ibuf, obuf);

	/* Look for "+" - if followed by a number,
	   assume it's an international number and leave
	   it alone.
	*/
	if ((p = strchr(ibuf, '+')) != NULL) {
		if (isdigit((u_char) *(p + 1))) {
			/* strip any non-digits */
			strip_nonnum(ibuf);
		}
	} else {
		strip_nonnum(ibuf);

		/* Apply local munges */
		munge_phone(ibuf, obuf);
		strcpy(ibuf, obuf);
	}

	/* Convert string of form abcd to remote-printer@d.c.b.a.tpc.int */
	q = obuf;
	for (p = ibuf + strlen(ibuf) - 1; p >= ibuf; p--) {
		*q++ = *p;
		*q++ = '.';
	}
	*q = '\0';
	strcpy(ibuf, obuf);
	strcpy(obuf, "remote-printer");

	/* include userinfo if present */
	if (userinfo != NULL && strlen(userinfo)) {
		strcat(obuf, ".");
		strcat(obuf, userinfo);
	}
	strcat(obuf, "@");
	strcat(obuf, ibuf);		/* tack on reversed phone number */
	strcat(obuf, TPCDOMAIN);	/* tack on domain name */
	p = strdup(obuf);
	return(p);
}

/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1992, 1993  Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/termios.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap.h>

#include "ldap_defaults.h"
#include "ud.h"

void
printbase( char *lead, char *s )
{
	register char **cp;
	char **rdns;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->printbase(%s, %s)\n", lead, s);
#endif
	if (s == NULL) {
		printf("%sroot\n", lead);
		return;
	}
	printf("%s", lead);
	rdns = ldap_explode_dn(s, TRUE);
	for (cp = rdns; ; ) {
		printf("%s", friendly_name(*cp));
		cp++;
		if (*cp == NULL) {
			printf("\n");
			break;
		}
		else
			printf(", ");
	}
	ldap_value_free(rdns);
	return;
}

void
fetch_buffer( char *buffer, int length, FILE *where )
{
	register int i;
    	char *p;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->fetch_buffer(%x, %d, %x)\n", buffer, length, where);
#endif
	/*
	 *  Fetch a buffer and strip off any leading or trailing non-printing
	 *  characters, namely newlines and carriage returns.
	 */
	if (fgets(buffer, length, where) == NULL) {
		if (feof(where))
			errno = 0;	 /* so fatal() doesn't bitch */
		fatal("fgets");
	}
	for (i = strlen(buffer) - 1;
	     i >= 0 && !isprint((unsigned char) buffer[i]); i--)
		buffer[i] = '\0';

	p = buffer;
	while ( *p != '\0' ) {
		if ( isprint( (unsigned char) *p )) {
			++p;
		} else {
			SAFEMEMCPY( p, p + 1, strlen( p + 1 ) + 1 ); 
		}
	}

}

void
fatal( char *s )
{
	if (errno != 0)
		perror(s);
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	destroy_tickets();
#endif
	exit( EXIT_FAILURE );
}

int
isgroup( void )
{
	char **vp;
	register int i;
	int group = FALSE;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->isgroup()\n");
#endif
	if ((i = attr_to_index("objectClass")) == -1)
		return(FALSE);
	vp = Entry.attrs[i].values;
	for (i = 0; *vp != NULL; vp++) {
#ifdef DEBUG
		i++;
		if (debug & D_GROUPS)
			printf("class #%1d: (%s)\n", i, *vp);
#endif
		if (!strcmp(*vp, "rfc822MailGroup"))
			group = TRUE;
	}
	return(group);
}

/*
 *  Print out the string 's' on a field of 'width' chracters.  Each line
 *  should be indented 'lead' characters.
 */
void
format( char *str, int width, int lead )
{
	char *s, *original, *leader = "";
	register char *cp;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->format(%s, %d, %d)\n", str, width, lead);
#endif
	if (lead >= width) {
		fprintf(stderr, "  Cannot format (%s, %d, %d)\n", str, width, lead);
		return;
	}
	if (lead > 0) {
		leader = (char *) Malloc((unsigned) (lead + 1));
		(void) memset(leader, ' ', lead);
		*(leader + lead) = '\0';
	}

	/*
	 *  Some compilers get really unhappy with this function since it
	 *  fiddles around with the first argument, which could be a string
	 *  constant.  We do a strdup() here so we can do whatever the hell
	 *  we want.
	 */
	s = original = strdup(str);
	for (;;) {
		if (((int) strlen(s) + lead) < width) {
			printf("%s%s\n", leader, s);
			Free(leader);
			Free(original);
			return; 
			/*NOTREACHED*/
		}
		cp = s + width - lead;
		while (!isspace((unsigned char)*cp) && (cp != s))
			cp--;
		*cp = '\0';
		while (isspace((unsigned char)*s))
			s++;
		printf("%s%s\n", leader, s);
		s = cp + 1;
	}
}

/*
 *  Print out the string 's' on a field of 'width' chracters.  The first line
 *  should be indented 'first_indent' spaces, then followed by 'first_tag', 
 *  and then followed by the first line of 's'.  Subsequent lines should be
 *  indented 'indent' spaces, then followed by 'tag', and then followed by
 *  subsequent lines of 's'.
 */
void
format2(
    char *s,
    char *first_tag,
    char *tag,
    int first_indent,
    int indent,
    int width
)
{
	char c, *fi, *i;
	register char *cp;

	if (first_tag == NULL)
		first_tag = "";
	if (tag == NULL)
		tag = "";
#ifdef DEBUG
	if (debug & D_TRACE)
		printf("format2(\"%s\", \"%s\", \"%s\", %1d, %1d, %1d)\n", s, 
				first_tag, tag, first_indent, indent, width);
#endif

	/* make sure the indents are sane */
	if ((first_indent >= width) || (indent >= width)) {
		fprintf(stderr, "  Cannot format:  indent too large\n");
		return;
	}

	/* make the indentations */
	if (first_indent > 0) {
		fi = (char *) Malloc((unsigned) (first_indent + 1));
		(void) memset(fi, ' ', first_indent);
		*(fi + first_indent) = '\0';
	}
	else
		fi = "";
	if (indent > 0) {
		i = (char *) Malloc((unsigned) (indent + 1));
		(void) memset(i, ' ', indent);
		*(i + indent) = '\0';
	}
	else
		i = "";

	/* now do the first line */
	if (((int) strlen(s) + (int) strlen(first_tag) + first_indent) < width) {
		printf("%s%s%s\n", fi, first_tag, s);
		Free(fi);
		Free(i);
		return; 
		/*NOTREACHED*/
	}

	/*
	 *  's' points to the beginning of the string we want to print.
	 *  We point 'cp' to the end of the maximum amount of text we
	 *  can print (i.e., total width less the indentation and the
	 *  length of the tag).  Once we have set 'cp' initially we
	 *  back it up to the first space character.
	 */
	cp = s + width - first_indent - strlen(first_tag);
	while (!isspace((unsigned char)*cp) && (cp != s))
		cp--;

	/*
	 *  Once there, we change that space character to a null, print the
	 *  string, and then restore the space character.
	 */
	c = *cp;
	*cp = '\0';
	printf("%s%s%s\n", fi, first_tag, s);
	*cp = c;

	/*
	 *  Since 'cp' may have been set to a space initially (and so no
	 *  back-tracking was performed), it could have a space after it
	 *  as well.  We should gobble up all of these since we don't want
	 *  unexpected leading blanks.
	 */  
	for (s = cp + 1; isspace((unsigned char)*s); s++)
		;

	/* now do all of the other lines */
	for (;;) {
		if (((int) strlen(s) + (int) strlen(tag) + indent) < width) {
			printf("%s%s%s\n", i, tag, s);
			Free(fi);
			Free(i);
			return; 
			/*NOTREACHED*/
		}
		cp = s + width - indent - strlen(tag);
		while (!isspace((unsigned char)*cp) && (cp != s))
			cp--;
		c = *cp;
		*cp = '\0';
		printf("%s%s%s\n", i, tag, s);
		s = cp + 1;
		*cp = c;			/* don't mess up 's' */
	}
}

#define IN_A_QUOTE   0
#define OUT_OF_QUOTE 1

char *
strip_ignore_chars( char *cp )
{
	int had_a_comma = FALSE;
	int flag = OUT_OF_QUOTE;
	register char *rcp, *cp1;
	char *tmp;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("strip_ignore_chars(%s)\n", cp);
#endif
	for (rcp = cp; *rcp != '\0'; rcp++)
		if (isignorechar(*rcp) || (*rcp == '"'))
			break;
	if (*rcp == '\0')
		return(cp);

	cp1 = tmp = (char *) Malloc((unsigned) strlen(cp));
	for (rcp = cp; *rcp != '\0'; rcp++) {
		/* toss quotes and flip the flag */
		if (*rcp == '"')
			flag = OUT_OF_QUOTE - flag;
		else if (isignorechar(*rcp)) {
			if (flag == OUT_OF_QUOTE)
				*cp1++ = ' ';
			else
				*cp1++ = *rcp;
		}
		else if (*rcp == ',') {
			*cp1++ = *rcp;
			had_a_comma = TRUE;
		}
		else 
			*cp1++ = *rcp;
	}
	*cp1 = '\0';

	/* re-quote the name if it had a comma in it */
	if (had_a_comma == TRUE) {
		rcp = cp1 = (char *) Malloc((unsigned) (strlen(tmp) + 3));
		*rcp++ = '"';
		*rcp = '\0';
		strcat(rcp, tmp);
		strcat(rcp, "\"");
		Free(tmp);
		tmp = cp1;
	}
	return(tmp);
}

char *
code_to_str( int i )
{
	switch(i) {
	case LDAP_MOD_ADD : return("ADD");
	case LDAP_MOD_DELETE : return("DELETE");
	case LDAP_MOD_REPLACE : return("REPLACE");
	default : return("?????");
	}
}

char *
friendly_name( char *s )
{
	static LDAPFriendlyMap *map = NULL;
	static char *cp;

	cp = ldap_friendly_name(FRIENDLYFILE, s, &map);
	if (cp == NULL)
		return(s);
	return(cp);
}

#ifdef UOFM

/* return TRUE if s has the syntax of a uniqname */
int
isauniqname( char *s )
{
	int i = strlen(s);

	if ((i < 3) || (i > 8))		/* uniqnames are 3-8 chars */
		return(FALSE);
	if (!isalpha((unsigned char)*s)) /* uniqnames begin with a letter */
		return(FALSE);
	for ( ; *s != '\0'; s++)	/* uniqnames are alphanumeric */
		if (!isalnum((unsigned char)*s))
			return(FALSE);
	return(TRUE);
}
#endif

/* return TRUE if this attribute should be printed as a DN */
int
isadn( char *s )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		if (!strcasecmp(s, attrlist[i].quipu_name))
			break;
	if (attrlist[i].flags & ATTR_FLAG_IS_A_DN)
		return(TRUE);
	return(FALSE);
}

char *
my_ldap_dn2ufn( char *s )
{
#ifdef UD_BASE
	register char **cpp;
	static char short_DN[BUFSIZ];

	if (strstr(s, UD_BASE) == NULL)
		return(ldap_dn2ufn(s));
	cpp = ldap_explode_dn(s, TRUE);
	sprintf(short_DN, "%s, %s", *cpp, *(cpp + 1));
	ldap_value_free(cpp);
	return(short_DN);
#else
	return(ldap_dn2ufn(s));
#endif
}

/* return TRUE if this attribute should be printed as a URL */
int
isaurl( char *s )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		if (!strcasecmp(s, attrlist[i].quipu_name))
			break;
	if (attrlist[i].flags & ATTR_FLAG_IS_A_URL)
		return(TRUE);
	return(FALSE);
}

/* return TRUE if this attribute should be printed as a date and time */
int
isadate( char *s )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		if (!strcasecmp(s, attrlist[i].quipu_name))
			break;
	if (attrlist[i].flags & ATTR_FLAG_IS_A_DATE)
		return(TRUE);
	return(FALSE);
}

void *
Malloc( unsigned int size )
{
	void *void_ptr;

	void_ptr = (void *) malloc(size);
	if (void_ptr == NULL) {
		perror("malloc");
		exit( EXIT_FAILURE );
		/*NOTREACHED*/
	}
	return(void_ptr);
}

void
Free( void *ptr )
{
	free(ptr);
}

char *
nextstr( char *s )
{
	while (isspace((unsigned char) *s) && (*s != '\0'))
		s++;
	if (s == NULL)
		return(NULL);
	if (*s == '\0')
		return(NULL);
	return(s);
}

void
free_mod_struct( LDAPMod *modp )
{
	if (modp->mod_values != NULL)
		(void) ldap_value_free(modp->mod_values);
	Free(modp->mod_type);
	Free(modp);
}

void
StrFreeDup( char **ptr, char *new_value )
{
	if (*ptr != NULL)
		Free(*ptr);
	if (new_value == NULL)
		*ptr = NULL;
	else
		*ptr = strdup(new_value);
}


int
confirm_action( char *msg )
{ 
        char 	tmp[SMALL_BUF_SIZE];
	int	i;

	if ( msg != NULL ) {
		putchar( '\n' );
		format( msg, 75, 2 );
	}

	printf("\n  Is this OK? ");
	fflush(stdout);
	tmp[0] = '\0';
	fetch_buffer(tmp, sizeof(tmp), stdin);
	i = strlen(tmp);
	return( i > 0 &&
	    ( !strncasecmp(tmp, "YES", i) || !strncasecmp(tmp, "OK", i)));
}

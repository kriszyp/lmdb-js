/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1991, 1993 
 * Regents of the University of Michigan.  All rights reserved.
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

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#include <ldap.h>

#include "ud.h"

struct entry Entry;

static char *time2text(char *ldtimestr, int dateonly);
static long		gtime(struct tm *tm);

/*
 *  When displaying entries, display only these attributes, and in this
 *  order.
 */
static char *person_attr_print_order[] = {
	"cn",
	"mail",
	"telephoneNumber",
	"facsimileTelephoneNumber",
	"pager",
	"postalAddress",
	"title",
	"uid",
	"multiLineDescription",
	"homePhone",
	"homePostalAddress",
	"drink",
	"labeledURL",
	"onVacation",
	"vacationMessage",
	"memberOfGroup",
	"lastModifiedBy",
	"lastModifiedTime",
	"modifiersname",
	"modifytimestamp",
	NULL
};

static char *group_attr_print_order[] = {
	"cn",
	"facsimileTelephoneNumber",
	"telephoneNumber",
	"postalAddress",
	"multiLineDescription",
	"joinable",
	"associatedDomain",
	"owner",
	"moderator",
	"ErrorsTo",
	"rfc822ErrorsTo",
	"RequestsTo",
	"rfc822RequestsTo",
	"member",
	"mail",
	"labeledURL",
	"lastModifiedBy",
	"lastModifiedTime",
	"modifiersname",
	"modifytimestamp",
	"creatorsname",
	"createtimestamp",
	NULL
};


void
parse_answer( LDAPMessage *s )
{
	int idx;
	char **rdns;
	register LDAPMessage *ep;
	register char *ap;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->parse_answer(%x)\n", s);
#endif

	clear_entry();

#ifdef DEBUG
	if (debug & D_PARSE)
		printf(" Done clearing entry\n");
#endif
	for (ep = ldap_first_entry(ld, s); ep != NULL; ep = ldap_next_entry(ld, ep)) {
		BerElement *cookie = NULL;
#ifdef DEBUG
		if (debug & D_PARSE)
			printf(" Determining DN and name\n");
#endif
		Entry.DN = ldap_get_dn(ld, ep);
#ifdef DEBUG
		if (debug & D_PARSE)
			printf(" DN = %s\n", Entry.DN);
#endif
		rdns = ldap_explode_dn(Entry.DN, TRUE);
#ifdef DEBUG
		if (debug & D_PARSE)
			printf(" Name = %s\n", *rdns);
#endif
		Entry.name = strdup(*rdns);
		ldap_value_free(rdns);
		for (ap = ldap_first_attribute(ld, ep, &cookie); ap != NULL; ap = ldap_next_attribute(ld, ep, cookie)) {

#ifdef DEBUG
			if (debug & D_PARSE)
				printf("parsing ap = %s\n", ap);
#endif
			if ((idx = attr_to_index(ap)) < 0) {
				printf("  Unknown attribute \"%s\"\n", ap);
				continue;
			}
			add_value(&(Entry.attrs[idx]), ep, ap);
		}

		if( cookie != NULL ) {
			ber_free( cookie, 0 );
		}
	}
#ifdef DEBUG
	if (debug & D_PARSE)
		printf(" Done parsing entry\n");
#endif
}

void
add_value( struct attribute *attr, LDAPMessage *ep, char *ap )
{
	register int i = 0;
	char **vp, **tp, **avp;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->add_value(%x, %x, %s)\n", attr, ep, ap);
#endif
	vp = (char **) ldap_get_values(ld, ep, ap);

	/*
	 *  Fill in the attribute structure for this attribute.  This
	 *  stores away the values (using strdup()) and the count.  Terminate
	 *  the list with a NULL pointer.
	 *
	 *  attr->quipu_name has already been set during initialization.
	 */
	if ((attr->number_of_values = ldap_count_values(vp)) > 0) {
		attr->values = (char **) Malloc((unsigned) ((attr->number_of_values + 1) * sizeof(char *)));
		avp = attr->values;

		for (i = 1, tp = vp; *tp != NULL; i++, tp++) {
#ifdef DEBUG
			if (debug & D_PARSE)
				printf("  value #%d  %s\n", i, *tp);
#endif
			/*
			 *  The 'name' field of the Entry structure already has
			 *  has the first part of the DN copied into it.  Thus,
			 *  we don't need to save it away here again.  Also, by
			 *  tossing it away here, we make printing this info out
			 *  a bit easier later.
			 */
			if (!strcmp(ap, "cn") && !strcmp(*tp, Entry.name)) {
				attr->number_of_values--;
				continue;
			}
			*avp++ = strdup(*tp);
		}
		*avp = NULL;
	}
	ldap_value_free(vp);
}

void
print_an_entry( void )
{
	int n = 0, i, idx;
	char is_a_group, **order;
	char *sub_list[MAX_VALUES], buf[SMALL_BUF_SIZE];

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_an_entry()\n");
#endif

	if( Entry.name == NULL ) {
		printf(" No Entry found.\n");
		return;
	}

	printf(" \"%s\"\n", Entry.name);
	
	/*
	 *  If the entry is a group, find all of the subscribers to that
	 *  group.  A subscriber is an entry that *points* to a group entry,
	 *  and a member is an entry that is included as part of a group
	 *  entry.
	 *
	 *  We also need to select the appropriate output format here.
	 */
	is_a_group = isgroup();
	if (is_a_group) {
		order = (char **) group_attr_print_order;
		n = find_all_subscribers(sub_list, Entry.DN);
#ifdef DEBUG
		if (debug & D_PRINT)
			printf(" Group \"%s\" has %d subscribers\n", 
								Entry.name, n);
#endif
	}
	else
		order = (char **) person_attr_print_order;

	for (i = 0; order[i] != NULL; i++) {
		idx = attr_to_index(order[i]);
#ifdef DEBUG
		if (debug & D_PRINT) {
			printf("  ATTR #%2d = %s [%s] (%d values)\n", i + 1,
				Entry.attrs[idx].output_string,
				Entry.attrs[idx].quipu_name,
				Entry.attrs[idx].number_of_values);
		}
#endif
		if (idx < 0)
			continue;
		if (Entry.attrs[idx].number_of_values == 0)
			continue;
		if (isadn(order[i]))
			print_DN(Entry.attrs[idx]);
		else if (isaurl(order[i]))
			print_URL(Entry.attrs[idx]);
		else if (isadate(order[i])) {
			/* fix time and date, then call usual routine */
			Entry.attrs[idx].values[0] = 
				time2text(Entry.attrs[idx].values[0], FALSE);
			print_values(Entry.attrs[idx]);
		}
		else
			print_values(Entry.attrs[idx]);
	}

	/*
	 *  If it is a group, then we should print the subscriber list (if
	 *  there are any).  If there are a lot of them, prompt the user
	 *  before printing them.
	 */
	if (is_a_group && (n > 0)) {
		char *label = "Subscribers:         ";

		if (n > TOO_MANY_TO_PRINT) {
			printf("  There are %d subscribers.  Print them? ", n);
			fflush(stdout);
			fetch_buffer(buf, sizeof(buf), stdin);
			if (!((buf[0] == 'y') || (buf[0] == 'Y')))
				return;
		}
		format2((char *) my_ldap_dn2ufn(sub_list[n - 1]), label, (char *) NULL, 2, 
						2 + strlen(label) + 1, col_size); 
		for (n--; n > 0; n--)
			format2((char *) my_ldap_dn2ufn(sub_list[n - 1]), (char *) NULL, 
				(char *) NULL, 2 + strlen(label), 
				2 + strlen(label) + 2, col_size); 
	}

	return;
}

#define OUT_LABEL_LEN	20

/* prints the values associated with an attribute */
void
print_values( struct attribute A )
{
	register int i, k;
	register char *cp, **vp;
	char out_buf[MED_BUF_SIZE], *padding = NULL;
	int lead;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_values(%x)\n", A);
#endif
	if (A.number_of_values == 0)
		return;
	if ((vp = A.values) == NULL)
		return;

	/*
	 *  Pad out the output string label so that it fills the
	 *  whole field of length OUT_LABEL_LEN.
	 */
	out_buf[0] = '\0';
	i = OUT_LABEL_LEN - strlen(A.output_string);
	if (i < 0) {
		printf("Output string for \"%s\" is too long.  Maximum length is %d characters\n", A.quipu_name, OUT_LABEL_LEN);
		return;
	}
	if (isgroup() && !strcmp(A.quipu_name, "mail") && (Entry.attrs[attr_to_index("member")].number_of_values == 0)) {
		A.output_string = "Members";
		i = OUT_LABEL_LEN - strlen(A.output_string);
		padding = (char *) Malloc((unsigned) (i + 1));
		(void) memset(padding, ' ', i);
		*(padding + i) = '\0';
		sprintf(out_buf, "%s:%s", A.output_string, padding);
	}
	else if (!(isgroup() && !strcmp(A.quipu_name, "mail") && (Entry.attrs[attr_to_index("member")].number_of_values > 0))) {
		padding = (char *) Malloc((unsigned) (i + 1));
		(void) memset(padding, ' ', i);
		*(padding + i) = '\0';
		sprintf(out_buf, "%s:%s", A.output_string, padding);
	}
	/*
	 *  If this happens to be a group, then do not print the output
	 *  string if we have already printed out some members.
	 */
	else if (isgroup() && !strcmp(A.quipu_name, "mail") && (Entry.attrs[attr_to_index("member")].number_of_values > 0)) {
		padding = (char *) Malloc((unsigned) (OUT_LABEL_LEN + 2));
		(void) memset(padding, ' ', OUT_LABEL_LEN + 1);
		*(padding + OUT_LABEL_LEN + 1) = '\0';
		sprintf(out_buf, "%s", padding);
	}
	lead = strlen(out_buf) + 2;

	printf("  %s", out_buf);
	for (i = 0; *vp != NULL; i++, vp++) {
		if (i > 0) {
			if (!strncmp(A.output_string, "Home a", 6) || !strncmp(A.output_string, "Business a", 10)) {
				printf("  %s", out_buf);
			}
			else {
				for (k = lead; k > 0; k--)
					putchar(' ');
			}
		}
		for (cp = *vp; *cp != '\0'; cp++) {
			switch (*cp) {
			case '$' :
				if (!strncmp(A.output_string, "Home a", 6) || !strncmp(A.output_string, "Business a", 10) || !strcmp(A.quipu_name, "multiLineDescription")) {
					putchar('\n');
					for (k = lead; k > 0; k--)
						putchar(' ');
					while (isspace((unsigned char) cp[1]))
						cp++;
				}
				else
					putchar(*cp);
				break;
			case '\n' :
				putchar('%');
				putchar('\n');
				break;
			default:
				putchar(*cp);
			}
		}
		putchar('\n');
	}
	if (padding != NULL)
		Free(padding);
	return;
}

/* prints the DN's associated with an attribute */
void
print_DN( struct attribute A )
{
	int i, lead;
	register char **vp;
	char out_buf[MED_BUF_SIZE], *padding = NULL;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_DN(%x)\n", A);
#endif
	if (A.number_of_values == 0)
		return;
	/*
	 *  Pad out the output string label so that it fills the
	 *  whole field of length OUT_LABEL_LEN.
	 */
	i = OUT_LABEL_LEN - strlen(A.output_string);
	if (i > 0) {
		padding = (char *) Malloc((unsigned) (i + 1));
		(void) memset(padding, ' ', i);
		*(padding + i) = '\0';
		sprintf(out_buf, "%s:%s", A.output_string, padding);
		(void) Free(padding);
	}
	lead = strlen(out_buf) + 2;

	vp = A.values;
	format2((char *) my_ldap_dn2ufn(*vp), out_buf, (char *) NULL, 2, lead + 1, col_size); 
	for (vp++; *vp != NULL; vp++) {
		format2((char *) my_ldap_dn2ufn(*vp), (char *) NULL, (char *) NULL, lead, 
			lead + 1, col_size); 
	}
	return;
}

void
clear_entry( void )
{
	register int i;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->clear_entry()\n");
	if ((debug & D_PRINT) && (Entry.name != NULL))
		printf(" Clearing entry \"%s\"\n", Entry.name);
#endif
	if (Entry.DN != NULL)
		ldap_memfree(Entry.DN);
	if (Entry.name != NULL)
		Free(Entry.name);
	Entry.may_join = FALSE;
	Entry.subscriber_count = -1;
	Entry.DN = Entry.name = NULL;

	/*  clear all of the values associated with all attributes */
	for (i = 0; attrlist[i].quipu_name != NULL; i++) {
#ifdef DEBUG
		if (debug & D_PRINT)
			printf(" Clearing attribute \"%s\" -- ", 
				Entry.attrs[i].quipu_name);
#endif
		if (Entry.attrs[i].values == NULL) {
#ifdef DEBUG
			if (debug & D_PRINT)
				printf(" no values, skipping\n");
#endif
			continue;
		}
#ifdef DEBUG
		if (debug & D_PRINT)
			printf(" freeing %d values\n", 
					Entry.attrs[i].number_of_values);
#endif
		Entry.attrs[i].number_of_values = 0;
		ldap_value_free(Entry.attrs[i].values);
		Entry.attrs[i].values = (char **) NULL;

		/*
		 *  Note:  We do not clear either of the char * fields
		 *  since they will always be applicable.
		 */
	}
}

int
attr_to_index( char *s )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		if (!strcasecmp(s, attrlist[i].quipu_name))
			return(i);
	return(-1);
}

void
initialize_attribute_strings( void )
{
	register int i;

	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		Entry.attrs[i].quipu_name = attrlist[i].quipu_name;
	for (i = 0; attrlist[i].quipu_name != NULL; i++)
		Entry.attrs[i].output_string = attrlist[i].output_string;
}

/* prints the URL/label pairs associated with an attribute */
void
print_URL( struct attribute A )
{
	int i, lead;
	register char **vp;
	char out_buf[MED_BUF_SIZE], *padding = NULL;

#ifdef DEBUG
	if (debug & D_TRACE)
		printf("->print_URL(%x)\n", A);
#endif
	if (A.number_of_values == 0)
		return;
	/*
	 *  Pad out the output string label so that it fills the
	 *  whole field of length OUT_LABEL_LEN.
	 */
	i = OUT_LABEL_LEN - strlen(A.output_string);
	if (i > 0) {
		padding = (char *) Malloc((unsigned) (i + 1));
		(void) memset(padding, ' ', i);
		*(padding + i) = '\0';
		sprintf(out_buf, "%s:%s", A.output_string, padding);
	}
	lead = strlen(out_buf) + 2;

	vp = A.values;
	print_one_URL(*vp, 2, out_buf, lead);
	for (vp++; *vp != NULL; vp++)
		print_one_URL(*vp, lead, (char *) NULL, lead);
	if (padding != NULL)
		Free(padding);
	return;
}

void
print_one_URL( char *s, int label_lead, char *tag, int url_lead )
{
	register int i;
	char c, *cp, *url;

	for (cp = s; !isspace((unsigned char)*cp) && (*cp != '\0'); cp++)
		;
	c = *cp;
	*cp = '\0';
	url = strdup(s);
	*cp = c;
	if (*cp != '\0') {
		for (cp++; isspace((unsigned char)*cp); cp++)
			;
	}
	else
		cp = "(no description available)";
	format2(cp, tag, (char *) NULL, label_lead, label_lead + 1, col_size);
	for (i = url_lead + 2; i > 0; i--)
		printf(" ");
	printf("%s\n", url);
	Free(url);
}


#define GET2BYTENUM( p )	(( *(p) - '0' ) * 10 + ( *((p)+1) - '0' ))

static char *
time2text( char *ldtimestr, int dateonly )
{
    struct tm		t;
    char		*p, *timestr, zone, *fmterr = "badly formatted time";
    time_t		gmttime;
	int ndigits;

	if (strlen( ldtimestr ) < 12 ) {
		return( fmterr );
	}

    for ( ndigits=0; isdigit((unsigned char) ldtimestr[ndigits]); ndigits++) {
		; /* EMPTY */
    }

	if ( ndigits != 12 && ndigits != 14) {
	    return( fmterr );
	}
	
    memset( (char *)&t, '\0', sizeof( struct tm ));

    p = ldtimestr;

	if( ndigits == 14) {
		/* came with a century */
		/* POSIX says tm_year should be year - 1900 */
    	t.tm_year = 100 * GET2BYTENUM( p ) - 1900;
		p += 2;
	} else {
    	t.tm_year = 0;
	}
    t.tm_year += GET2BYTENUM( p ); p += 2;

    t.tm_mon = GET2BYTENUM( p ) - 1; p += 2;
    t.tm_mday = GET2BYTENUM( p ); p += 2;
    t.tm_hour = GET2BYTENUM( p ); p += 2;
    t.tm_min = GET2BYTENUM( p ); p += 2;
    t.tm_sec = GET2BYTENUM( p ); p += 2;

    if (( zone = *p ) == 'Z' ) {	/* GMT */
	zone = '\0';	/* no need to indicate on screen, so we make it null */
    }

    gmttime = gtime( &t );
    timestr = ctime( &gmttime );

    timestr[ strlen( timestr ) - 1 ] = zone;	/* replace trailing newline */
    if ( dateonly ) {
		AC_MEMCPY( timestr + 11, timestr + 20, strlen( timestr + 20 ) + 1 );
    }

    return( strdup( timestr ) );
}


/* gtime.c - inverse gmtime */

#include <ac/time.h>

/* gtime(): the inverse of localtime().
	This routine was supplied by Mike Accetta at CMU many years ago.
 */

int	dmsize[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define	dysize(y)	\
	(((y) % 4) ? 365 : (((y) % 100) ? 366 : (((y) % 400) ? 365 : 366)))

/*
 * Y2K YEAR
 */
	/* per STDC & POSIX tm_year *should* be offset by 1900 */
#define YEAR_POSIX(y)		((y) + 1900)

	/*
	 * year is < 1900, year is offset by 1900
	 */
#define YEAR_CAREFUL(y)		((y) < 1900 ? (y) + 1900 : (y))

#define YEAR(y) YEAR_CAREFUL(y)


/*  */

static long
gtime( struct tm *tm )
{
    register int    i,
                    sec,
                    mins,
                    hour,
                    mday,
                    mon,
                    year;
    register long   result;

    if ((sec = tm -> tm_sec) < 0 || sec > 59
	    || (mins = tm -> tm_min) < 0 || mins > 59
	    || (hour = tm -> tm_hour) < 0 || hour > 24
	    || (mday = tm -> tm_mday) < 1 || mday > 31
	    || (mon = tm -> tm_mon + 1) < 1 || mon > 12)
	return ((long) -1);
    if (hour == 24) {
	hour = 0;
	mday++;
    }
    year = YEAR (tm -> tm_year);

    result = 0L;
    for (i = 1970; i < year; i++)
	result += dysize (i);
    if (dysize (year) == 366 && mon >= 3)
	result++;
    while (--mon)
	result += dmsize[mon - 1];
    result += mday - 1;
    result = 24 * result + hour;
    result = 60 * result + mins;
    result = 60 * result + sec;

    return result;
}

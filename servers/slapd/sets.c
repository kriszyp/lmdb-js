/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "sets.h"

static char **set_join (char **lset, int op, char **rset);
static char **set_chase (SET_GATHER gatherer, void *cookie, char **set, char *attr, int attrlen, int closure);
static int set_samedn (char *dn1, char *dn2);

long
set_size (char **set)
{
	int i;

	i = 0;
	if (set != NULL) {
		while (set[i])
			i++;
	}
	return(i);
}

void
set_dispose (char **set)
{
	int i;

	if (set != NULL) {
		for (i = 0; set[i]; i++)
			ch_free(set[i]);
		ch_free(set);
	}
}

static char **
set_join (char **lset, int op, char **rset)
{
	char **set;
	long i, j, last;

	set = NULL;
	if (op == '|') {
		if (lset == NULL || *lset == NULL) {
			if (rset == NULL) {
				if (lset == NULL)
					return(ch_calloc(1, sizeof(char *)));
				return(lset);
			}
			set_dispose(lset);
			return(rset);
		}
		if (rset == NULL || *rset == NULL) {
			set_dispose(rset);
			return(lset);
		}

		i = set_size(lset) + set_size(rset) + 1;
		set = ch_calloc(i, sizeof(char *));
		if (set != NULL) {
			/* set_chase() depends on this routine to
			 * keep the first elements of the result
			 * set the same (and in the same order)
			 * as the left-set.
			 */
			for (i = 0; lset[i]; i++)
				set[i] = lset[i];
			ch_free(lset);
			for (i = 0; rset[i]; i++) {
				for (j = 0; set[j]; j++) {
					if (set_samedn(rset[i], set[j])) {
						ch_free(rset[i]);
						rset[i] = NULL;
						break;		
					}	
				}
				if (rset[i])
					set[j] = rset[i];
			}
			ch_free(rset);
		}
		return(set);
	}

	if (op == '&') {
		if (lset == NULL || *lset == NULL || rset == NULL || *rset == NULL) {
			set = ch_calloc(1, sizeof(char *));
		} else {
			set = lset;
			lset = NULL;
			last = set_size(set) - 1;
			for (i = 0; set[i]; i++) {
				for (j = 0; rset[j]; j++) {
					if (set_samedn(set[i], rset[j]))
						break;
				}
				if (rset[j] == NULL) {
					ch_free(set[i]);
					set[i] = set[last];
					set[last] = NULL;
					last--;
					i--;
				}
			}
		}
	}

	set_dispose(lset);
	set_dispose(rset);
	return(set);
}

static char **
set_chase (SET_GATHER gatherer, void *cookie, char **set, char *attr, int attrlen, int closure)
{
	char **vals, **nset;
	char attrstr[32];
	int i;

	if (set == NULL)
		return(ch_calloc(1, sizeof(char *)));

	if (*set == NULL)
		return(set);

	if (attrlen > (sizeof(attrstr) - 1)) {
		set_dispose(set);
		return(NULL);
	}
	memcpy(attrstr, attr, attrlen);
	attrstr[attrlen] = 0;

	nset = ch_calloc(1, sizeof(char *));
	if (nset == NULL) {
		set_dispose(set);
		return(NULL);
	}
	for (i = 0; set[i]; i++) {
		vals = (gatherer)(cookie, set[i], attrstr);
		if (vals != NULL)
			nset = set_join(nset, '|', vals);
	}
	set_dispose(set);

	if (closure) {
		for (i = 0; nset[i]; i++) {
			vals = (gatherer)(cookie, nset[i], attrstr);
			if (vals != NULL) {
				nset = set_join(nset, '|', vals);
				if (nset == NULL)
					break;
			}
		}
	}
	return(nset);
}

static int
set_samedn (char *dn1, char *dn2)
{
	char c1, c2;

	while (*dn1 == ' ') dn1++;
	while (*dn2 == ' ') dn2++;
	while (*dn1 || *dn2) {
		if (*dn1 != '=' && *dn1 != ','
			&& *dn2 != '=' && *dn2 != ',')
		{
			c1 = *dn1++;
			c2 = *dn2++;
			if (c1 >= 'a' && c1 <= 'z')
				c1 -= 'a' - 'A';
			if (c2 >= 'a' && c2 <= 'z')
				c2 -= 'a' - 'A';
			if (c1 != c2)
				return(0);
		} else {
			while (*dn1 == ' ') dn1++;
			while (*dn2 == ' ') dn2++;
			if (*dn1++ != *dn2++)
				return(0);
			while (*dn1 == ' ') dn1++;
			while (*dn2 == ' ') dn2++;
		}
	}
	return(1);
}

int
set_filter (SET_GATHER gatherer, void *cookie, char *filter, char *user, char *this, char ***results)
{
#	define IS_SET(x)	( (long)(x) >= 256 )
#	define IS_OP(x)	( (long)(x) < 256 )
#	define SF_ERROR(x)	{ rc = -1; goto _error; }
#	define SF_TOP()	(char **)( (stp < 0) ? 0 : stack[stp] )
#	define SF_POP()	(char **)( (stp < 0) ? 0 : stack[stp--] )
#	define SF_PUSH(x)	{ if (stp >= 63) SF_ERROR(overflow); stack[++stp] = (char **)(long)(x); }
	char c;
	char **set, **lset;
	int len, op, rc, stp;
	char **stack[64];

	if (results)
		*results = NULL;

	stp = -1;
	while (c = *filter++) {
		set = NULL;
		switch (c) {
		case ' ':
		case '\t':
		case '\x0A':
		case '\x0D':
			break;

		case '(':
			if (IS_SET(SF_TOP()))
				SF_ERROR(syntax);
			SF_PUSH(c);
			break;

		case ')':
			set = SF_POP();
			if (IS_OP(set))
				SF_ERROR(syntax);
			if (SF_TOP() == (void *)'(') {
				SF_POP();
				SF_PUSH(set);
				set = NULL;
			} else if (IS_OP(SF_TOP())) {
				op = (long)SF_POP();
				lset = SF_POP();
				SF_POP();
				set = set_join(lset, op, set);
				if (set == NULL)
					SF_ERROR(memory);
				SF_PUSH(set);
				set = NULL;
			} else {
				SF_ERROR(syntax);
			}
			break;

		case '&':
		case '|':
			set = SF_POP();
			if (IS_OP(set))
				SF_ERROR(syntax);
			if (SF_TOP() == 0 || SF_TOP() == (void *)'(') {
				SF_PUSH(set);
				set = NULL;
			} else if (IS_OP(SF_TOP())) {
				op = (long)SF_POP();
				lset = SF_POP();
				set = set_join(lset, op, set);
				if (set == NULL)
					SF_ERROR(memory);
				SF_PUSH(set);
				set = NULL;
			} else {
				SF_ERROR(syntax);
			}
			SF_PUSH(c);
			break;

		case '[':
			if ((SF_TOP() == (void *)'/') || IS_SET(SF_TOP()))
				SF_ERROR(syntax);
			for (	len = 0;
					(c = *filter++) && (c != ']');
					len++)
			{ }
			if (c == 0)
				SF_ERROR(syntax);
			
			set = ch_calloc(2, sizeof(char *));
			if (set == NULL)
				SF_ERROR(memory);
			*set = ch_calloc(len + 1, sizeof(char));
			if (*set == NULL)
				SF_ERROR(memory);
			memcpy(*set, &filter[-len - 1], len);
			SF_PUSH(set);
			set = NULL;
			break;

		case '-':
			c = *filter++;
			if (c != '>')
				SF_ERROR(syntax);
			/* fall through to next case */

		case '/':
			if (IS_OP(SF_TOP()))
				SF_ERROR(syntax);
			SF_PUSH('/');
			break;

		default:
			if ((c != '_')
				&& (c < 'A' || c > 'Z')
				&& (c < 'a' || c > 'z'))
			{
				SF_ERROR(syntax);
			}
			filter--;
			for (	len = 1;
					(c = filter[len])
						&& ((c >= '0' && c <= '9')
							|| (c >= 'A' && c <= 'Z')
							|| (c >= 'a' && c <= 'z'));
					len++)
			{ }
			if (len == 4
				&& memcmp("this", filter, len) == 0)
			{
				if ((SF_TOP() == (void *)'/') || IS_SET(SF_TOP()))
					SF_ERROR(syntax);
				set = ch_calloc(2, sizeof(char *));
				if (set == NULL)
					SF_ERROR(memory);
				*set = ch_strdup(this);
				if (*set == NULL)
					SF_ERROR(memory);
			} else if (len == 4
				&& memcmp("user", filter, len) == 0) 
			{
				if ((SF_TOP() == (void *)'/') || IS_SET(SF_TOP()))
					SF_ERROR(syntax);
				set = ch_calloc(2, sizeof(char *));
				if (set == NULL)
					SF_ERROR(memory);
				*set = ch_strdup(user);
				if (*set == NULL)
					SF_ERROR(memory);
			} else if (SF_TOP() != (void *)'/') {
				SF_ERROR(syntax);
			} else {
				SF_POP();
				set = set_chase(gatherer, cookie, SF_POP(), filter, len, c == '*');
				if (set == NULL)
					SF_ERROR(memory);
				if (c == '*')
					len++;
			}
			filter += len;
			SF_PUSH(set);
			set = NULL;
			break;
		}
	}

	set = SF_POP();
	if (IS_OP(set))
		SF_ERROR(syntax);
	if (SF_TOP() == 0) {

	} else if (IS_OP(SF_TOP())) {
		op = (long)SF_POP();
		lset = SF_POP();
		set = set_join(lset, op, set);
		if (set == NULL)
			SF_ERROR(memory);
	} else {
		SF_ERROR(syntax);
	}

	rc = set_size(set);
	if (results) {
		*results = set;
		set = NULL;
	}

_error:
	if (IS_SET(set))
		set_dispose(set);
	while (set = SF_POP()) {
		if (IS_SET(set))
			set_dispose(set);
	}
	return(rc);
}

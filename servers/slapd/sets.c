/* $OpenLDAP$ */
/*
 * Copyright 2000-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "sets.h"

static BerVarray set_join (BerVarray lset, int op, BerVarray rset);
static BerVarray set_chase (SLAP_SET_GATHER gatherer,
	void *cookie, BerVarray set, struct berval *attr, int closure);
static int set_samedn (char *dn1, char *dn2);

long
slap_set_size (BerVarray set)
{
	long	i;

	i = 0;
	if (set != NULL) {
		while (set[i].bv_val)
			i++;
	}
	return i;
}

void
slap_set_dispose (BerVarray set)
{
	ber_bvarray_free(set);
}

static BerVarray
set_join (BerVarray lset, int op, BerVarray rset)
{
	BerVarray set;
	long i, j, last;

	set = NULL;
	if (op == '|') {
		if (lset == NULL || lset->bv_val == NULL) {
			if (rset == NULL) {
				if (lset == NULL)
					return(SLAP_CALLOC(1, sizeof(struct berval)));
				return(lset);
			}
			slap_set_dispose(lset);
			return(rset);
		}
		if (rset == NULL || rset->bv_val == NULL) {
			slap_set_dispose(rset);
			return(lset);
		}

		i = slap_set_size(lset) + slap_set_size(rset) + 1;
		set = SLAP_CALLOC(i, sizeof(struct berval));
		if (set != NULL) {
			/* set_chase() depends on this routine to
			 * keep the first elements of the result
			 * set the same (and in the same order)
			 * as the left-set.
			 */
			for (i = 0; lset[i].bv_val; i++)
				set[i] = lset[i];
			ch_free(lset);
			for (i = 0; rset[i].bv_val; i++) {
				for (j = 0; set[j].bv_val; j++) {
					if (set_samedn(rset[i].bv_val, set[j].bv_val)) {
						ch_free(rset[i].bv_val);
						rset[i].bv_val = NULL;
						break;		
					}	
				}
				if (rset[i].bv_val)
					set[j] = rset[i];
			}
			ch_free(rset);
		}
		return(set);
	}

	if (op == '&') {
		if (lset == NULL || lset->bv_val == NULL || rset == NULL || rset->bv_val == NULL) {
			set = SLAP_CALLOC(1, sizeof(struct berval));
		} else {
			set = lset;
			lset = NULL;
			last = slap_set_size(set) - 1;
			for (i = 0; set[i].bv_val; i++) {
				for (j = 0; rset[j].bv_val; j++) {
					if (set_samedn(set[i].bv_val, rset[j].bv_val))
						break;
				}
				if (rset[j].bv_val == NULL) {
					ch_free(set[i].bv_val);
					set[i] = set[last];
					set[last].bv_val = NULL;
					last--;
					i--;
				}
			}
		}
	}

	slap_set_dispose(lset);
	slap_set_dispose(rset);
	return(set);
}

static BerVarray
set_chase (SLAP_SET_GATHER gatherer,
	void *cookie, BerVarray set, struct berval *attr, int closure)
{
	BerVarray vals, nset;
	char attrstr[32];
	struct berval bv;
	int i;

	bv.bv_len = attr->bv_len;
	bv.bv_val = attrstr;

	if (set == NULL)
		return(SLAP_CALLOC(1, sizeof(struct berval)));

	if (set->bv_val == NULL)
		return(set);

	if (attr->bv_len > (sizeof(attrstr) - 1)) {
		slap_set_dispose(set);
		return(NULL);
	}
	AC_MEMCPY(attrstr, attr->bv_val, attr->bv_len);
	attrstr[attr->bv_len] = 0;

	nset = SLAP_CALLOC(1, sizeof(struct berval));
	if (nset == NULL) {
		slap_set_dispose(set);
		return(NULL);
	}
	for (i = 0; set[i].bv_val; i++) {
		vals = (gatherer)(cookie, &set[i], &bv);
		if (vals != NULL)
			nset = set_join(nset, '|', vals);
	}
	slap_set_dispose(set);

	if (closure) {
		for (i = 0; nset[i].bv_val; i++) {
			vals = (gatherer)(cookie, &nset[i], &bv);
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
slap_set_filter (SLAP_SET_GATHER gatherer,
	void *cookie, struct berval *fbv,
	struct berval *user, struct berval *this, BerVarray *results)
{
#define IS_SET(x)	( (long)(x) >= 256 )
#define IS_OP(x)	( (long)(x) < 256 )
#define SF_ERROR(x)	do { rc = -1; goto _error; } while (0)
#define SF_TOP()	( (BerVarray)( (stp < 0) ? 0 : stack[stp] ) )
#define SF_POP()	( (BerVarray)( (stp < 0) ? 0 : stack[stp--] ) )
#define SF_PUSH(x)	do { \
		if (stp >= 63) SF_ERROR(overflow); \
		stack[++stp] = (BerVarray)(long)(x); \
	} while (0)

	BerVarray set, lset;
	BerVarray stack[64];
	int len, op, rc, stp;
	char c, *filter = fbv->bv_val;

	if (results)
		*results = NULL;

	stp = -1;
	while ((c = *filter++)) {
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
			
			set = SLAP_CALLOC(2, sizeof(struct berval));
			if (set == NULL)
				SF_ERROR(memory);
			set->bv_val = SLAP_CALLOC(len + 1, sizeof(char));
			if (set->bv_val == NULL)
				SF_ERROR(memory);
			AC_MEMCPY(set->bv_val, &filter[-len - 1], len);
			set->bv_len = len;
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
				set = SLAP_CALLOC(2, sizeof(struct berval));
				if (set == NULL)
					SF_ERROR(memory);
				ber_dupbv( set, this );
				if (set->bv_val == NULL)
					SF_ERROR(memory);
			} else if (len == 4
				&& memcmp("user", filter, len) == 0) 
			{
				if ((SF_TOP() == (void *)'/') || IS_SET(SF_TOP()))
					SF_ERROR(syntax);
				set = SLAP_CALLOC(2, sizeof(struct berval));
				if (set == NULL)
					SF_ERROR(memory);
				ber_dupbv( set, user );
				if (set->bv_val == NULL)
					SF_ERROR(memory);
			} else if (SF_TOP() != (void *)'/') {
				SF_ERROR(syntax);
			} else {
				struct berval fb2;
				SF_POP();
				fb2.bv_val = filter;
				fb2.bv_len = len;
				set = set_chase(gatherer,
					cookie, SF_POP(), &fb2, c == '*');
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

	rc = slap_set_size(set) > 0 ? 1 : 0;
	if (results) {
		*results = set;
		set = NULL;
	}

_error:
	if (IS_SET(set))
		slap_set_dispose(set);
	while ((set = SF_POP())) {
		if (IS_SET(set))
			slap_set_dispose(set);
	}
	return(rc);
}

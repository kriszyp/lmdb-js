/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "sets.h"

static BerVarray set_chase( SLAP_SET_GATHER gatherer,
	SetCookie *cookie, BerVarray set, AttributeDescription *desc, int closure );

static long
slap_set_size( BerVarray set )
{
	long	i;

	i = 0;
	if ( set != NULL ) {
		while ( !BER_BVISNULL( &set[i] ) ) {
			i++;
		}
	}
	return i;
}

static void
slap_set_dispose( SetCookie *cp, BerVarray set )
{
	ber_bvarray_free_x(set, cp->op->o_tmpmemctx);
}

BerVarray
slap_set_join (SetCookie *cp, BerVarray lset, int op, BerVarray rset)
{
	BerVarray set;
	long i, j, last;

	set = NULL;
	if (op == '|') {
		if (lset == NULL || lset->bv_val == NULL) {
			if (rset == NULL) {
				if (lset == NULL)
					return(cp->op->o_tmpcalloc(1, sizeof(struct berval),
						cp->op->o_tmpmemctx));
				return(lset);
			}
			slap_set_dispose(cp, lset);
			return(rset);
		}
		if (rset == NULL || rset->bv_val == NULL) {
			slap_set_dispose(cp, rset);
			return(lset);
		}

		i = slap_set_size(lset) + slap_set_size(rset) + 1;
		set = cp->op->o_tmpcalloc(i, sizeof(struct berval), cp->op->o_tmpmemctx);
		if (set != NULL) {
			/* set_chase() depends on this routine to
			 * keep the first elements of the result
			 * set the same (and in the same order)
			 * as the left-set.
			 */
			for (i = 0; lset[i].bv_val; i++)
				set[i] = lset[i];
			cp->op->o_tmpfree(lset, cp->op->o_tmpmemctx);
			for (i = 0; rset[i].bv_val; i++) {
				for (j = 0; set[j].bv_val; j++) {
					if ( dn_match( &rset[i], &set[j] ) )
					{
						cp->op->o_tmpfree(rset[i].bv_val, cp->op->o_tmpmemctx);
						rset[i].bv_val = NULL;
						break;		
					}	
				}
				if (rset[i].bv_val)
					set[j] = rset[i];
			}
			cp->op->o_tmpfree(rset, cp->op->o_tmpmemctx);
		}
		return(set);
	}

	if (op == '&') {
		if (lset == NULL || lset->bv_val == NULL || rset == NULL || rset->bv_val == NULL) {
			set = cp->op->o_tmpcalloc(1, sizeof(struct berval), cp->op->o_tmpmemctx);
		} else {
			set = lset;
			lset = NULL;
			last = slap_set_size(set) - 1;
			for (i = 0; set[i].bv_val; i++) {
				for (j = 0; rset[j].bv_val; j++) {
					if ( dn_match( &set[i], &rset[j] ) ) {
						break;
					}
				}
				if (rset[j].bv_val == NULL) {
					cp->op->o_tmpfree(set[i].bv_val, cp->op->o_tmpmemctx);
					set[i] = set[last];
					set[last].bv_val = NULL;
					last--;
					i--;
				}
			}
		}
	}

	slap_set_dispose(cp, lset);
	slap_set_dispose(cp, rset);
	return(set);
}

static BerVarray
set_chase( SLAP_SET_GATHER gatherer,
	SetCookie *cp, BerVarray set, AttributeDescription *desc, int closure )
{
	BerVarray vals, nset;
	int i;

	if (set == NULL)
		return cp->op->o_tmpcalloc( 1, sizeof(struct berval),
				cp->op->o_tmpmemctx );

	if ( BER_BVISNULL( set ) )
		return set;

	nset = cp->op->o_tmpcalloc( 1, sizeof(struct berval), cp->op->o_tmpmemctx );
	if ( nset == NULL ) {
		slap_set_dispose( cp, set );
		return NULL;
	}
	for ( i = 0; !BER_BVISNULL( &set[i] ); i++ ) {
		vals = (gatherer)( cp, &set[i], desc );
		if ( vals != NULL ) {
			nset = slap_set_join( cp, nset, '|', vals );
		}
	}
	slap_set_dispose( cp, set );

	if ( closure ) {
		for ( i = 0; !BER_BVISNULL( &nset[i] ); i++ ) {
			vals = (gatherer)( cp, &nset[i], desc );
			if ( vals != NULL ) {
				nset = slap_set_join( cp, nset, '|', vals );
				if ( nset == NULL ) {
					break;
				}
			}
		}
	}

	return nset;
}

int
slap_set_filter( SLAP_SET_GATHER gatherer,
	SetCookie *cp, struct berval *fbv,
	struct berval *user, struct berval *target, BerVarray *results )
{
#define IS_SET(x)	( (unsigned long)(x) >= 256 )
#define IS_OP(x)	( (unsigned long)(x) < 256 )
#define SF_ERROR(x)	do { rc = -1; goto _error; } while (0)
#define SF_TOP()	( (BerVarray)( (stp < 0) ? 0 : stack[stp] ) )
#define SF_POP()	( (BerVarray)( (stp < 0) ? 0 : stack[stp--] ) )
#define SF_PUSH(x)	do { \
		if (stp >= 63) SF_ERROR(overflow); \
		stack[++stp] = (BerVarray)(long)(x); \
	} while (0)

	BerVarray set, lset;
	BerVarray stack[64] = { 0 };
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
				set = slap_set_join(cp, lset, op, set);
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
				set = slap_set_join(cp, lset, op, set);
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
			for ( len = 0; (c = *filter++) && (c != ']'); len++ )
				;
			if (c == 0)
				SF_ERROR(syntax);
			
			set = cp->op->o_tmpcalloc(2, sizeof(struct berval), cp->op->o_tmpmemctx);
			if (set == NULL)
				SF_ERROR(memory);
			set->bv_val = cp->op->o_tmpcalloc(len + 1, sizeof(char), cp->op->o_tmpmemctx);
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
				set = cp->op->o_tmpcalloc(2, sizeof(struct berval), cp->op->o_tmpmemctx);
				if (set == NULL)
					SF_ERROR(memory);
				ber_dupbv_x( set, target, cp->op->o_tmpmemctx );
				if (set->bv_val == NULL)
					SF_ERROR(memory);
			} else if (len == 4
				&& memcmp("user", filter, len) == 0) 
			{
				if ((SF_TOP() == (void *)'/') || IS_SET(SF_TOP()))
					SF_ERROR(syntax);
				set = cp->op->o_tmpcalloc(2, sizeof(struct berval), cp->op->o_tmpmemctx);
				if (set == NULL)
					SF_ERROR(memory);
				ber_dupbv_x( set, user, cp->op->o_tmpmemctx );
				if (set->bv_val == NULL)
					SF_ERROR(memory);
			} else if (SF_TOP() != (void *)'/') {
				SF_ERROR(syntax);
			} else {
				struct berval		fb2;
				AttributeDescription	*ad = NULL;
				const char		*text = NULL;

				SF_POP();
				fb2.bv_val = filter;
				fb2.bv_len = len;

				if ( slap_bv2ad( &fb2, &ad, &text ) != LDAP_SUCCESS ) {
					SF_ERROR(syntax);
				}
				
				set = set_chase( gatherer,
					cp, SF_POP(), ad, c == '*' );
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
		set = slap_set_join(cp, lset, op, set);
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
		slap_set_dispose(cp, set);
	while ((set = SF_POP())) {
		if (IS_SET(set))
			slap_set_dispose(cp, set);
	}
	return(rc);
}

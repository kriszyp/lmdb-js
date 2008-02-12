/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2008 The OpenLDAP Foundation.
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
		while ( !BER_BVISNULL( &set[ i ] ) ) {
			i++;
		}
	}
	return i;
}

static int
slap_set_isempty( BerVarray set )
{
	if ( set == NULL ) {
		return 1;
	}

	if ( !BER_BVISNULL( &set[ 0 ] ) ) {
		return 0;
	}

	return 1;
}

static void
slap_set_dispose( SetCookie *cp, BerVarray set, unsigned flags )
{
	if ( flags & SLAP_SET_REFVAL ) {
		if ( ! ( flags & SLAP_SET_REFARR ) ) {
			cp->set_op->o_tmpfree( set, cp->set_op->o_tmpmemctx );
		}

	} else {
		ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
	}
}

static BerVarray
set_dup( SetCookie *cp, BerVarray set, unsigned flags )
{
	BerVarray	newset = NULL;

	if ( set == NULL ) {
		return NULL;
	}

	if ( flags & SLAP_SET_REFARR ) {
		int	i;

		for ( i = 0; !BER_BVISNULL( &set[ i ] ); i++ )
			;
		newset = cp->set_op->o_tmpcalloc( i + 1,
				sizeof( struct berval ), 
				cp->set_op->o_tmpmemctx );
		if ( newset == NULL ) {
			return NULL;
		}

		if ( flags & SLAP_SET_REFVAL ) {
			for ( i = 0; !BER_BVISNULL( &set[ i ] ); i++ ) {
				ber_dupbv_x( &newset[ i ], &set[ i ],
						cp->set_op->o_tmpmemctx );
			}

		} else {
			AC_MEMCPY( newset, set, ( i + 1 ) * sizeof( struct berval ) );
		}
		
	} else {
		newset = set;
	}

	return newset;
}

BerVarray
slap_set_join(
	SetCookie	*cp,
	BerVarray	lset,
	unsigned	op_flags,
	BerVarray	rset )
{
	BerVarray	set;
	long		i, j, last, rlast;
	unsigned	op = ( op_flags & SLAP_SET_OPMASK );

	set = NULL;
	switch ( op ) {
	case '|':	/* union */
		if ( lset == NULL || BER_BVISNULL( &lset[ 0 ] ) ) {
			if ( rset == NULL ) {
				if ( lset == NULL ) {
					set = cp->set_op->o_tmpcalloc( 1,
							sizeof( struct berval ),
							cp->set_op->o_tmpmemctx );
					BER_BVZERO( &set[ 0 ] );
					return set;
				}
				return set_dup( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
			}
			slap_set_dispose( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
			return set_dup( cp, rset, SLAP_SET_RREF2REF( op_flags ) );
		}
		if ( rset == NULL || BER_BVISNULL( &rset[ 0 ] ) ) {
			slap_set_dispose( cp, rset, SLAP_SET_RREF2REF( op_flags ) );
			return set_dup( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
		}

		/* worst scenario: no duplicates */
		rlast = slap_set_size( rset );
		i = slap_set_size( lset ) + rlast + 1;
		set = cp->set_op->o_tmpcalloc( i, sizeof( struct berval ), cp->set_op->o_tmpmemctx );
		if ( set != NULL ) {
			/* set_chase() depends on this routine to
			 * keep the first elements of the result
			 * set the same (and in the same order)
			 * as the left-set.
			 */
			for ( i = 0; !BER_BVISNULL( &lset[ i ] ); i++ ) {
				if ( op_flags & SLAP_SET_LREFVAL ) {
					ber_dupbv_x( &set[ i ], &lset[ i ], cp->set_op->o_tmpmemctx );

				} else {
					set[ i ] = lset[ i ];
				}
			}

			/* pointers to values have been used in set - don't free twice */
			op_flags |= SLAP_SET_LREFVAL;

			last = i;

			for ( i = 0; !BER_BVISNULL( &rset[ i ] ); i++ ) {
				int	exists = 0;

				for ( j = 0; !BER_BVISNULL( &set[ j ] ); j++ ) {
					if ( bvmatch( &rset[ i ], &set[ j ] ) )
					{
						if ( !( op_flags & SLAP_SET_RREFVAL ) ) {
							cp->set_op->o_tmpfree( rset[ i ].bv_val, cp->set_op->o_tmpmemctx );
							rset[ i ] = rset[ --rlast ];
							BER_BVZERO( &rset[ rlast ] );
						}
						exists = 1;
						break;
					}
				}

				if ( !exists ) {
					if ( op_flags & SLAP_SET_RREFVAL ) {
						ber_dupbv_x( &set[ last ], &rset[ i ], cp->set_op->o_tmpmemctx );

					} else {
						set[ last ] = rset[ i ];
					}
					last++;
				}
			}

			/* pointers to values have been used in set - don't free twice */
			op_flags |= SLAP_SET_RREFVAL;

			BER_BVZERO( &set[ last ] );
		}
		break;

	case '&':	/* intersection */
		if ( lset == NULL || BER_BVISNULL( &lset[ 0 ] )
			|| rset == NULL || BER_BVISNULL( &rset[ 0 ] ) )
		{
			set = cp->set_op->o_tmpcalloc( 1, sizeof( struct berval ),
					cp->set_op->o_tmpmemctx );
			BER_BVZERO( &set[ 0 ] );
			break;

		} else {
			long llen, rlen;
			BerVarray sset;

			llen = slap_set_size( lset );
			rlen = slap_set_size( rset );

			/* dup the shortest */
			if ( llen < rlen ) {
				last = llen;
				set = set_dup( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
				lset = NULL;
				sset = rset;

			} else {
				last = rlen;
				set = set_dup( cp, rset, SLAP_SET_RREF2REF( op_flags ) );
				rset = NULL;
				sset = lset;
			}

			if ( set == NULL ) {
				break;
			}

			for ( i = 0; !BER_BVISNULL( &set[ i ] ); i++ ) {
				for ( j = 0; !BER_BVISNULL( &sset[ j ] ); j++ ) {
					if ( bvmatch( &set[ i ], &sset[ j ] ) ) {
						break;
					}
				}

				if ( BER_BVISNULL( &sset[ j ] ) ) {
					cp->set_op->o_tmpfree( set[ i ].bv_val, cp->set_op->o_tmpmemctx );
					set[ i ] = set[ --last ];
					BER_BVZERO( &set[ last ] );
					i--;
				}
			}
		}
		break;

	case '+':	/* string concatenation */
		i = slap_set_size( rset );
		j = slap_set_size( lset );

		/* handle empty set cases */
		if ( i == 0 ) {
			if ( j == 0 ) {
				set = cp->set_op->o_tmpcalloc( i * j + 1, sizeof( struct berval ),
						cp->set_op->o_tmpmemctx );
				if ( set == NULL ) {
					break;
				}
				BER_BVZERO( &set[ 0 ] );
				break;

			} else {
				set = set_dup( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
				lset = NULL;
				break;
			}

		} else if ( j == 0 ) {
			set = set_dup( cp, rset, SLAP_SET_RREF2REF( op_flags ) );
			rset = NULL;
			break;
		}

		set = cp->set_op->o_tmpcalloc( i * j + 1, sizeof( struct berval ),
				cp->set_op->o_tmpmemctx );
		if ( set == NULL ) {
			break;
		}

		for ( last = 0, i = 0; !BER_BVISNULL( &lset[ i ] ); i++ ) {
			for ( j = 0; !BER_BVISNULL( &rset[ j ] ); j++ ) {
				struct berval	bv;
				long		k;

				/* don't concatenate with the empty string */
				if ( BER_BVISEMPTY( &lset[ i ] ) ) {
					ber_dupbv_x( &bv, &rset[ j ], cp->set_op->o_tmpmemctx );
					if ( bv.bv_val == NULL ) {
						ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
						set = NULL;
						goto done;
					}

				} else if ( BER_BVISEMPTY( &rset[ j ] ) ) {
					ber_dupbv_x( &bv, &lset[ i ], cp->set_op->o_tmpmemctx );
					if ( bv.bv_val == NULL ) {
						ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
						set = NULL;
						goto done;
					}

				} else {
					bv.bv_len = lset[ i ].bv_len + rset[ j ].bv_len;
					bv.bv_val = cp->set_op->o_tmpalloc( bv.bv_len + 1,
							cp->set_op->o_tmpmemctx );
					if ( bv.bv_val == NULL ) {
						ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
						set = NULL;
						goto done;
					}
					AC_MEMCPY( bv.bv_val, lset[ i ].bv_val, lset[ i ].bv_len );
					AC_MEMCPY( &bv.bv_val[ lset[ i ].bv_len ], rset[ j ].bv_val, rset[ j ].bv_len );
					bv.bv_val[ bv.bv_len ] = '\0';
				}

				for ( k = 0; k < last; k++ ) {
					if ( bvmatch( &set[ k ], &bv ) ) {
						cp->set_op->o_tmpfree( bv.bv_val, cp->set_op->o_tmpmemctx );
						break;
					}
				}

				if ( k == last ) {
					set[ last++ ] = bv;
				}
			}
		}
		BER_BVZERO( &set[ last ] );
		break;

	default:
		break;
	}

done:;
	if ( lset ) slap_set_dispose( cp, lset, SLAP_SET_LREF2REF( op_flags ) );
	if ( rset ) slap_set_dispose( cp, rset, SLAP_SET_RREF2REF( op_flags ) );

	return set;
}

static BerVarray
set_chase( SLAP_SET_GATHER gatherer,
	SetCookie *cp, BerVarray set, AttributeDescription *desc, int closure )
{
	BerVarray	vals, nset;
	int		i;

	if ( set == NULL ) {
		set = cp->set_op->o_tmpcalloc( 1, sizeof( struct berval ),
				cp->set_op->o_tmpmemctx );
		if ( set != NULL ) {
			BER_BVZERO( &set[ 0 ] );
		}
		return set;
	}

	if ( BER_BVISNULL( set ) ) {
		return set;
	}

	nset = cp->set_op->o_tmpcalloc( 1, sizeof( struct berval ), cp->set_op->o_tmpmemctx );
	if ( nset == NULL ) {
		ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
		return NULL;
	}
	for ( i = 0; !BER_BVISNULL( &set[ i ] ); i++ ) {
		vals = gatherer( cp, &set[ i ], desc );
		if ( vals != NULL ) {
			nset = slap_set_join( cp, nset, '|', vals );
		}
	}
	ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );

	if ( closure ) {
		for ( i = 0; !BER_BVISNULL( &nset[ i ] ); i++ ) {
			vals = gatherer( cp, &nset[ i ], desc );
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
#define STACK_SIZE	64
#define IS_SET(x)	( (unsigned long)(x) >= 256 )
#define IS_OP(x)	( (unsigned long)(x) < 256 )
#define SF_ERROR(x)	do { rc = -1; goto _error; } while ( 0 )
#define SF_TOP()	( (BerVarray)( ( stp < 0 ) ? 0 : stack[ stp ] ) )
#define SF_POP()	( (BerVarray)( ( stp < 0 ) ? 0 : stack[ stp-- ] ) )
#define SF_PUSH(x)	do { \
		if ( stp >= ( STACK_SIZE - 1 ) ) SF_ERROR( overflow ); \
		stack[ ++stp ] = (BerVarray)(long)(x); \
	} while ( 0 )

	BerVarray	set, lset;
	BerVarray	stack[ STACK_SIZE ] = { 0 };
	int		len, rc, stp;
	unsigned long	op;
	char		c, *filter = fbv->bv_val;

	if ( results ) {
		*results = NULL;
	}

	stp = -1;
	while ( ( c = *filter++ ) ) {
		set = NULL;
		switch ( c ) {
		case ' ':
		case '\t':
		case '\x0A':
		case '\x0D':
			break;

		case '(' /* ) */ :
			if ( IS_SET( SF_TOP() ) ) {
				SF_ERROR( syntax );
			}
			SF_PUSH( c );
			break;

		case /* ( */ ')':
			set = SF_POP();
			if ( IS_OP( set ) ) {
				SF_ERROR( syntax );
			}
			if ( SF_TOP() == (void *)'(' /* ) */ ) {
				SF_POP();
				SF_PUSH( set );
				set = NULL;

			} else if ( IS_OP( SF_TOP() ) ) {
				op = (unsigned long)SF_POP();
				lset = SF_POP();
				SF_POP();
				set = slap_set_join( cp, lset, op, set );
				if ( set == NULL ) {
					SF_ERROR( memory );
				}
				SF_PUSH( set );
				set = NULL;

			} else {
				SF_ERROR( syntax );
			}
			break;

		case '|':	/* union */
		case '&':	/* intersection */
		case '+':	/* string concatenation */
			set = SF_POP();
			if ( IS_OP( set ) ) {
				SF_ERROR( syntax );
			}
			if ( SF_TOP() == 0 || SF_TOP() == (void *)'(' /* ) */ ) {
				SF_PUSH( set );
				set = NULL;

			} else if ( IS_OP( SF_TOP() ) ) {
				op = (unsigned long)SF_POP();
				lset = SF_POP();
				set = slap_set_join( cp, lset, op, set );
				if ( set == NULL ) {
					SF_ERROR( memory );
				}
				SF_PUSH( set );
				set = NULL;
				
			} else {
				SF_ERROR( syntax );
			}
			SF_PUSH( c );
			break;

		case '[' /* ] */:
			if ( ( SF_TOP() == (void *)'/' ) || IS_SET( SF_TOP() ) ) {
				SF_ERROR( syntax );
			}
			for ( len = 0; ( c = *filter++ ) && ( c != /* [ */ ']' ); len++ )
				;
			if ( c == 0 ) {
				SF_ERROR( syntax );
			}
			
			set = cp->set_op->o_tmpcalloc( 2, sizeof( struct berval ),
					cp->set_op->o_tmpmemctx );
			if ( set == NULL ) {
				SF_ERROR( memory );
			}
			set->bv_val = cp->set_op->o_tmpcalloc( len + 1, sizeof( char ),
					cp->set_op->o_tmpmemctx );
			if ( BER_BVISNULL( set ) ) {
				SF_ERROR( memory );
			}
			AC_MEMCPY( set->bv_val, &filter[ - len - 1 ], len );
			set->bv_len = len;
			SF_PUSH( set );
			set = NULL;
			break;

		case '-':
			c = *filter++;
			if ( c != '>' ) {
				SF_ERROR( syntax );
			}
			/* fall through to next case */

		case '/':
			if ( IS_OP( SF_TOP() ) ) {
				SF_ERROR( syntax );
			}
			SF_PUSH( '/' );
			break;

		default:
			if ( ( c != '_' )
					&& ( c < 'A' || c > 'Z' )
					&& ( c < 'a' || c > 'z' ) )
			{
				SF_ERROR( syntax );
			}
			filter--;
			for ( len = 1;
					( c = filter[ len ] )
						&& ( ( c >= '0' && c <= '9' )
							|| ( c >= 'A' && c <= 'Z' )
							|| ( c >= 'a' && c <= 'z' ) );
					len++ )
				/* count */ ;
			if ( len == 4
				&& memcmp( "this", filter, len ) == 0 )
			{
				if ( ( SF_TOP() == (void *)'/' ) || IS_SET( SF_TOP() ) ) {
					SF_ERROR( syntax );
				}
				set = cp->set_op->o_tmpcalloc( 2, sizeof( struct berval ),
						cp->set_op->o_tmpmemctx );
				if ( set == NULL ) {
					SF_ERROR( memory );
				}
				ber_dupbv_x( set, target, cp->set_op->o_tmpmemctx );
				if ( BER_BVISNULL( set ) ) {
					SF_ERROR( memory );
				}
				BER_BVZERO( &set[ 1 ] );
				
			} else if ( len == 4
				&& memcmp( "user", filter, len ) == 0 ) 
			{
				if ( ( SF_TOP() == (void *)'/' ) || IS_SET( SF_TOP() ) ) {
					SF_ERROR( syntax );
				}
				set = cp->set_op->o_tmpcalloc( 2, sizeof( struct berval ),
						cp->set_op->o_tmpmemctx );
				if ( set == NULL ) {
					SF_ERROR( memory );
				}
				ber_dupbv_x( set, user, cp->set_op->o_tmpmemctx );
				if ( BER_BVISNULL( set ) ) {
					SF_ERROR( memory );
				}
				BER_BVZERO( &set[ 1 ] );
				
			} else if ( SF_TOP() != (void *)'/' ) {
				SF_ERROR( syntax );

			} else {
				struct berval		fb2;
				AttributeDescription	*ad = NULL;
				const char		*text = NULL;

				SF_POP();
				fb2.bv_val = filter;
				fb2.bv_len = len;

				if ( slap_bv2ad( &fb2, &ad, &text ) != LDAP_SUCCESS ) {
					SF_ERROR( syntax );
				}

				/* NOTE: ad must have distinguishedName syntax
				 * or expand in an LDAP URI if c == '*'
				 */
				
				set = set_chase( gatherer,
					cp, SF_POP(), ad, c == '*' );
				if ( set == NULL ) {
					SF_ERROR( memory );
				}
				if ( c == '*' ) {
					len++;
				}
			}
			filter += len;
			SF_PUSH( set );
			set = NULL;
			break;
		}
	}

	set = SF_POP();
	if ( IS_OP( set ) ) {
		SF_ERROR( syntax );
	}
	if ( SF_TOP() == 0 ) {
		/* FIXME: ok ? */ ;

	} else if ( IS_OP( SF_TOP() ) ) {
		op = (unsigned long)SF_POP();
		lset = SF_POP();
		set = slap_set_join( cp, lset, op, set );
		if ( set == NULL ) {
			SF_ERROR( memory );
		}
		
	} else {
		SF_ERROR( syntax );
	}

	rc = slap_set_isempty( set ) ? 0 : 1;
	if ( results ) {
		*results = set;
		set = NULL;
	}

_error:
	if ( IS_SET( set ) ) {
		ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
	}
	while ( ( set = SF_POP() ) ) {
		if ( IS_SET( set ) ) {
			ber_bvarray_free_x( set, cp->set_op->o_tmpmemctx );
		}
	}
	return rc;
}

/* avl.c - routines to implement an avl tree */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1993 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *   Hallvard B. Furuseth
 *   Kurt D. Zeilenga
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#ifdef CSRIMALLOC
#define ber_memalloc malloc
#define ber_memrealloc realloc
#define ber_memfree free
#else
#include "lber.h"
#endif

#define AVL_INTERNAL
#include "avl.h"

#define ROTATERIGHT(x)	{ \
	Avlnode *tmp;\
	if ( *(x) == NULL || (*(x))->avl_left == NULL ) {\
		(void) fputs("RR error\n", stderr); exit( EXIT_FAILURE ); \
	}\
	tmp = (*(x))->avl_left;\
	(*(x))->avl_left = tmp->avl_right;\
	tmp->avl_right = *(x);\
	*(x) = tmp;\
}
#define ROTATELEFT(x)	{ \
	Avlnode *tmp;\
	if ( *(x) == NULL || (*(x))->avl_right == NULL ) {\
		(void) fputs("RL error\n", stderr); exit( EXIT_FAILURE ); \
	}\
	tmp = (*(x))->avl_right;\
	(*(x))->avl_right = tmp->avl_left;\
	tmp->avl_left = *(x);\
	*(x) = tmp;\
}

/*
 * ravl_insert - called from avl_insert() to do a recursive insert into
 * and balance of an avl tree.
 */

static int
ravl_insert(
    Avlnode	**iroot,
    void*	data,
    int		*taller,
    AVL_CMP		fcmp,			/* comparison function */
    AVL_DUP		fdup,			/* function to call for duplicates */
    int		depth
)
{
	int	rc, cmp, tallersub;
	Avlnode	*l, *r;

	if ( *iroot == 0 ) {
		if ( (*iroot = (Avlnode *) ber_memalloc( sizeof( Avlnode ) ))
		    == NULL ) {
			return( -1 );
		}
		(*iroot)->avl_left = 0;
		(*iroot)->avl_right = 0;
		(*iroot)->avl_bf = 0;
		(*iroot)->avl_data = data;
		*taller = 1;
		return( 0 );
	}

	cmp = (*fcmp)( data, (*iroot)->avl_data );

	/* equal - duplicate name */
	if ( cmp == 0 ) {
		*taller = 0;
		return( (*fdup)( (*iroot)->avl_data, data ) );
	}

	/* go right */
	else if ( cmp > 0 ) {
		rc = ravl_insert( &((*iroot)->avl_right), data, &tallersub,
		   fcmp, fdup, depth );
		if ( tallersub )
			switch ( (*iroot)->avl_bf ) {
			case LH	: /* left high - balance is restored */
				(*iroot)->avl_bf = EH;
				*taller = 0;
				break;
			case EH	: /* equal height - now right heavy */
				(*iroot)->avl_bf = RH;
				*taller = 1;
				break;
			case RH	: /* right heavy to start - right balance */
				r = (*iroot)->avl_right;
				switch ( r->avl_bf ) {
				case LH	: /* double rotation left */
					l = r->avl_left;
					switch ( l->avl_bf ) {
					case LH	: (*iroot)->avl_bf = EH;
						  r->avl_bf = RH;
						  break;
					case EH	: (*iroot)->avl_bf = EH;
						  r->avl_bf = EH;
						  break;
					case RH	: (*iroot)->avl_bf = LH;
						  r->avl_bf = EH;
						  break;
					}
					l->avl_bf = EH;
					ROTATERIGHT( (&r) )
					(*iroot)->avl_right = r;
					ROTATELEFT( iroot )
					*taller = 0;
					break;
				case EH	: /* This should never happen */
					break;
				case RH	: /* single rotation left */
					(*iroot)->avl_bf = EH;
					r->avl_bf = EH;
					ROTATELEFT( iroot )
					*taller = 0;
					break;
				}
				break;
			}
		else
			*taller = 0;
	}

	/* go left */
	else {
		rc = ravl_insert( &((*iroot)->avl_left), data, &tallersub,
		   fcmp, fdup, depth );
		if ( tallersub )
			switch ( (*iroot)->avl_bf ) {
			case LH	: /* left high to start - left balance */
				l = (*iroot)->avl_left;
				switch ( l->avl_bf ) {
				case LH	: /* single rotation right */
					(*iroot)->avl_bf = EH;
					l->avl_bf = EH;
					ROTATERIGHT( iroot )
					*taller = 0;
					break;
				case EH	: /* this should never happen */
					break;
				case RH	: /* double rotation right */
					r = l->avl_right;
					switch ( r->avl_bf ) {
					case LH	: (*iroot)->avl_bf = RH;
						  l->avl_bf = EH;
						  break;
					case EH	: (*iroot)->avl_bf = EH;
						  l->avl_bf = EH;
						  break;
					case RH	: (*iroot)->avl_bf = EH;
						  l->avl_bf = LH;
						  break;
					}
					r->avl_bf = EH;
					ROTATELEFT( (&l) )
					(*iroot)->avl_left = l;
					ROTATERIGHT( iroot )
					*taller = 0;
					break;
				}
				break;
			case EH	: /* equal height - now left heavy */
				(*iroot)->avl_bf = LH;
				*taller = 1;
				break;
			case RH	: /* right high - balance is restored */
				(*iroot)->avl_bf = EH;
				*taller = 0;
				break;
			}
		else
			*taller = 0;
	}

	return( rc );
}

/*
 * avl_insert -- insert a node containing data data into the avl tree
 * with root root.  fcmp is a function to call to compare the data portion
 * of two nodes.  it should take two arguments and return <, >, or == 0,
 * depending on whether its first argument is <, >, or == its second
 * argument (like strcmp, e.g.).  fdup is a function to call when a duplicate
 * node is inserted.  it should return 0, or -1 and its return value
 * will be the return value from avl_insert in the case of a duplicate node.
 * the function will be called with the original node's data as its first
 * argument and with the incoming duplicate node's data as its second
 * argument.  this could be used, for example, to keep a count with each
 * node.
 *
 * NOTE: this routine may malloc memory
 */

int
avl_insert( Avlnode **root, void* data, AVL_CMP fcmp, AVL_DUP fdup )
{
	int	taller;

	return( ravl_insert( root, data, &taller, fcmp, fdup, 0 ) );
}

/* 
 * right_balance() - called from delete when root's right subtree has
 * been shortened because of a deletion.
 */

static int
right_balance( Avlnode **root )
{
	int	shorter = -1;
	Avlnode	*r, *l;

	switch( (*root)->avl_bf ) {
	case RH:	/* was right high - equal now */
		(*root)->avl_bf = EH;
		shorter = 1;
		break;
	case EH:	/* was equal - left high now */
		(*root)->avl_bf = LH;
		shorter = 0;
		break;
	case LH:	/* was right high - balance */
		l = (*root)->avl_left;
		switch ( l->avl_bf ) {
		case RH	: /* double rotation left */
			r = l->avl_right;
			switch ( r->avl_bf ) {
			case RH	:
				(*root)->avl_bf = EH;
				l->avl_bf = LH;
				break;
			case EH	:
				(*root)->avl_bf = EH;
				l->avl_bf = EH;
				break;
			case LH	:
				(*root)->avl_bf = RH;
				l->avl_bf = EH;
				break;
			}
			r->avl_bf = EH;
			ROTATELEFT( (&l) )
			(*root)->avl_left = l;
			ROTATERIGHT( root )
			shorter = 1;
			break;
		case EH	: /* right rotation */
			(*root)->avl_bf = LH;
			l->avl_bf = RH;
			ROTATERIGHT( root );
			shorter = 0;
			break;
		case LH	: /* single rotation right */
			(*root)->avl_bf = EH;
			l->avl_bf = EH;
			ROTATERIGHT( root )
			shorter = 1;
			break;
		}
		break;
	}

	return( shorter );
}

/* 
 * left_balance() - called from delete when root's left subtree has
 * been shortened because of a deletion.
 */

static int
left_balance( Avlnode **root )
{
	int	shorter = -1;
	Avlnode	*r, *l;

	switch( (*root)->avl_bf ) {
	case LH:	/* was left high - equal now */
		(*root)->avl_bf = EH;
		shorter = 1;
		break;
	case EH:	/* was equal - right high now */
		(*root)->avl_bf = RH;
		shorter = 0;
		break;
	case RH:	/* was right high - balance */
		r = (*root)->avl_right;
		switch ( r->avl_bf ) {
		case LH	: /* double rotation left */
			l = r->avl_left;
			switch ( l->avl_bf ) {
			case LH	:
				(*root)->avl_bf = EH;
				r->avl_bf = RH;
				break;
			case EH	:
				(*root)->avl_bf = EH;
				r->avl_bf = EH;
				break;
			case RH	:
				(*root)->avl_bf = LH;
				r->avl_bf = EH;
				break;
			}
			l->avl_bf = EH;
			ROTATERIGHT( (&r) )
			(*root)->avl_right = r;
			ROTATELEFT( root )
			shorter = 1;
			break;
		case EH	: /* single rotation left */
			(*root)->avl_bf = RH;
			r->avl_bf = LH;
			ROTATELEFT( root );
			shorter = 0;
			break;
		case RH	: /* single rotation left */
			(*root)->avl_bf = EH;
			r->avl_bf = EH;
			ROTATELEFT( root )
			shorter = 1;
			break;
		}
		break;
	}

	return( shorter );
}

/*
 * ravl_delete() - called from avl_delete to do recursive deletion of a
 * node from an avl tree.  It finds the node recursively, deletes it,
 * and returns shorter if the tree is shorter after the deletion and
 * rebalancing.
 */

static void*
ravl_delete( Avlnode **root, void* data, AVL_CMP fcmp, int *shorter )
{
	int	shortersubtree = 0;
	int	cmp;
	void*	savedata;
	Avlnode	*minnode, *savenode;

	if ( *root == NULLAVL )
		return( 0 );

	cmp = (*fcmp)( data, (*root)->avl_data );

	/* found it! */
	if ( cmp == 0 ) {
		savenode = *root;
		savedata = savenode->avl_data;

		/* simple cases: no left child */
		if ( (*root)->avl_left == 0 ) {
			*root = (*root)->avl_right;
			*shorter = 1;
			ber_memfree( (char *) savenode );
			return( savedata );
		/* no right child */
		} else if ( (*root)->avl_right == 0 ) {
			*root = (*root)->avl_left;
			*shorter = 1;
			ber_memfree( (char *) savenode );
			return( savedata );
		}

		/* 
		 * avl_getmin will return to us the smallest node greater
		 * than the one we are trying to delete.  deleting this node
		 * from the right subtree is guaranteed to end in one of the
		 * simple cases above.
		 */

		minnode = (*root)->avl_right;
		while ( minnode->avl_left != NULLAVL )
			minnode = minnode->avl_left;

		/* swap the data */
		(*root)->avl_data = minnode->avl_data;
		minnode->avl_data = savedata;

		savedata = ravl_delete( &(*root)->avl_right, data, fcmp,
		    &shortersubtree );

		if ( shortersubtree )
			*shorter = right_balance( root );
		else
			*shorter = 0;
	/* go left */
	} else if ( cmp < 0 ) {
		if ( (savedata = ravl_delete( &(*root)->avl_left, data, fcmp,
		    &shortersubtree )) == 0 ) {
			*shorter = 0;
			return( 0 );
		}

		/* left subtree shorter? */
		if ( shortersubtree )
			*shorter = left_balance( root );
		else
			*shorter = 0;
	/* go right */
	} else {
		if ( (savedata = ravl_delete( &(*root)->avl_right, data, fcmp,
		    &shortersubtree )) == 0 ) {
			*shorter = 0;
			return( 0 );
		}

		if ( shortersubtree ) 
			*shorter = right_balance( root );
		else
			*shorter = 0;
	}

	return( savedata );
}

/*
 * avl_delete() - deletes the node containing data (according to fcmp) from
 * the avl tree rooted at root.
 */

void*
avl_delete( Avlnode **root, void* data, AVL_CMP fcmp )
{
	int	shorter;

	return( ravl_delete( root, data, fcmp, &shorter ) );
}

static int
avl_inapply( Avlnode *root, AVL_APPLY fn, void* arg, int stopflag )
{
	if ( root == 0 )
		return( AVL_NOMORE );

	if ( root->avl_left != 0 )
		if ( avl_inapply( root->avl_left, fn, arg, stopflag ) 
		    == stopflag )
			return( stopflag );

	if ( (*fn)( root->avl_data, arg ) == stopflag )
		return( stopflag );

	if ( root->avl_right == 0 )
		return( AVL_NOMORE );
	else
		return( avl_inapply( root->avl_right, fn, arg, stopflag ) );
}

static int
avl_postapply( Avlnode *root, AVL_APPLY fn, void* arg, int stopflag )
{
	if ( root == 0 )
		return( AVL_NOMORE );

	if ( root->avl_left != 0 )
		if ( avl_postapply( root->avl_left, fn, arg, stopflag ) 
		    == stopflag )
			return( stopflag );

	if ( root->avl_right != 0 )
		if ( avl_postapply( root->avl_right, fn, arg, stopflag ) 
		    == stopflag )
			return( stopflag );

	return( (*fn)( root->avl_data, arg ) );
}

static int
avl_preapply( Avlnode *root, AVL_APPLY fn, void* arg, int stopflag )
{
	if ( root == 0 )
		return( AVL_NOMORE );

	if ( (*fn)( root->avl_data, arg ) == stopflag )
		return( stopflag );

	if ( root->avl_left != 0 )
		if ( avl_preapply( root->avl_left, fn, arg, stopflag ) 
		    == stopflag )
			return( stopflag );

	if ( root->avl_right == 0 )
		return( AVL_NOMORE );
	else
		return( avl_preapply( root->avl_right, fn, arg, stopflag ) );
}

/*
 * avl_apply -- avl tree root is traversed, function fn is called with
 * arguments arg and the data portion of each node.  if fn returns stopflag,
 * the traversal is cut short, otherwise it continues.  Do not use -6 as
 * a stopflag, as this is what is used to indicate the traversal ran out
 * of nodes.
 */

int
avl_apply( Avlnode *root, AVL_APPLY fn, void* arg, int stopflag, int type )
{
	switch ( type ) {
	case AVL_INORDER:
		return( avl_inapply( root, fn, arg, stopflag ) );
	case AVL_PREORDER:
		return( avl_preapply( root, fn, arg, stopflag ) );
	case AVL_POSTORDER:
		return( avl_postapply( root, fn, arg, stopflag ) );
	default:
		fprintf( stderr, "Invalid traversal type %d\n", type );
		return( -1 );
	}

	/* NOTREACHED */
}

/*
 * avl_prefixapply - traverse avl tree root, applying function fprefix
 * to any nodes that match.  fcmp is called with data as its first arg
 * and the current node's data as its second arg.  it should return
 * 0 if they match, < 0 if data is less, and > 0 if data is greater.
 * the idea is to efficiently find all nodes that are prefixes of
 * some key...  Like avl_apply, this routine also takes a stopflag
 * and will return prematurely if fmatch returns this value.  Otherwise,
 * AVL_NOMORE is returned.
 */

int
avl_prefixapply(
    Avlnode	*root,
    void*	data,
    AVL_CMP		fmatch,
    void*	marg,
    AVL_CMP		fcmp,
    void*	carg,
    int		stopflag
)
{
	int	cmp;

	if ( root == 0 )
		return( AVL_NOMORE );

	cmp = (*fcmp)( data, root->avl_data /* , carg */);
	if ( cmp == 0 ) {
		if ( (*fmatch)( root->avl_data, marg ) == stopflag )
			return( stopflag );

		if ( root->avl_left != 0 )
			if ( avl_prefixapply( root->avl_left, data, fmatch,
			    marg, fcmp, carg, stopflag ) == stopflag )
				return( stopflag );

		if ( root->avl_right != 0 )
			return( avl_prefixapply( root->avl_right, data, fmatch,
			    marg, fcmp, carg, stopflag ) );
		else
			return( AVL_NOMORE );

	} else if ( cmp < 0 ) {
		if ( root->avl_left != 0 )
			return( avl_prefixapply( root->avl_left, data, fmatch,
			    marg, fcmp, carg, stopflag ) );
	} else {
		if ( root->avl_right != 0 )
			return( avl_prefixapply( root->avl_right, data, fmatch,
			    marg, fcmp, carg, stopflag ) );
	}

	return( AVL_NOMORE );
}

/*
 * avl_free -- traverse avltree root, freeing the memory it is using.
 * the dfree() is called to free the data portion of each node.  The
 * number of items actually freed is returned.
 */

int
avl_free( Avlnode *root, AVL_FREE dfree )
{
	int	nleft, nright;

	if ( root == 0 )
		return( 0 );

	nleft = nright = 0;
	if ( root->avl_left != 0 )
		nleft = avl_free( root->avl_left, dfree );

	if ( root->avl_right != 0 )
		nright = avl_free( root->avl_right, dfree );

	if ( dfree )
		(*dfree)( root->avl_data );
	ber_memfree( root );

	return( nleft + nright + 1 );
}

/*
 * avl_find -- search avltree root for a node with data data.  the function
 * cmp is used to compare things.  it is called with data as its first arg 
 * and the current node data as its second.  it should return 0 if they match,
 * < 0 if arg1 is less than arg2 and > 0 if arg1 is greater than arg2.
 */

void*
avl_find( Avlnode *root, const void* data, AVL_CMP fcmp )
{
	int	cmp;

	while ( root != 0 && (cmp = (*fcmp)( data, root->avl_data )) != 0 ) {
		if ( cmp < 0 )
			root = root->avl_left;
		else
			root = root->avl_right;
	}

	return( root ? root->avl_data : 0 );
}

/*
 * avl_find_lin -- search avltree root linearly for a node with data data. 
 * the function cmp is used to compare things.  it is called with data as its
 * first arg and the current node data as its second.  it should return 0 if
 * they match, non-zero otherwise.
 */

void*
avl_find_lin( Avlnode *root, const void* data, AVL_CMP fcmp )
{
	void*	res;

	if ( root == 0 )
		return( NULL );

	if ( (*fcmp)( data, root->avl_data ) == 0 )
		return( root->avl_data );

	if ( root->avl_left != 0 )
		if ( (res = avl_find_lin( root->avl_left, data, fcmp ))
		    != NULL )
			return( res );

	if ( root->avl_right == 0 )
		return( NULL );
	else
		return( avl_find_lin( root->avl_right, data, fcmp ) );
}

/* NON-REENTRANT INTERFACE */

static void*	*avl_list;
static int	avl_maxlist;
static int	avl_nextlist;

#define AVL_GRABSIZE	100

/* ARGSUSED */
static int
avl_buildlist( void* data, void* arg )
{
	static int	slots;

	if ( avl_list == (void* *) 0 ) {
		avl_list = (void* *) ber_memalloc(AVL_GRABSIZE * sizeof(void*));
		slots = AVL_GRABSIZE;
		avl_maxlist = 0;
	} else if ( avl_maxlist == slots ) {
		slots += AVL_GRABSIZE;
		avl_list = (void* *) ber_memrealloc( (char *) avl_list,
		    (unsigned) slots * sizeof(void*));
	}

	avl_list[ avl_maxlist++ ] = data;

	return( 0 );
}

/*
 * avl_getfirst() and avl_getnext() are provided as alternate tree
 * traversal methods, to be used when a single function cannot be
 * provided to be called with every node in the tree.  avl_getfirst()
 * traverses the tree and builds a linear list of all the nodes,
 * returning the first node.  avl_getnext() returns the next thing
 * on the list built by avl_getfirst().  This means that avl_getfirst()
 * can take a while, and that the tree should not be messed with while
 * being traversed in this way, and that multiple traversals (even of
 * different trees) cannot be active at once.
 */

void*
avl_getfirst( Avlnode *root )
{
	if ( avl_list ) {
		ber_memfree( (char *) avl_list);
		avl_list = (void* *) 0;
	}
	avl_maxlist = 0;
	avl_nextlist = 0;

	if ( root == 0 )
		return( 0 );

	(void) avl_apply( root, avl_buildlist, (void*) 0, -1, AVL_INORDER );

	return( avl_list[ avl_nextlist++ ] );
}

void*
avl_getnext( void )
{
	if ( avl_list == 0 )
		return( 0 );

	if ( avl_nextlist == avl_maxlist ) {
		ber_memfree( (void*) avl_list);
		avl_list = (void* *) 0;
		return( 0 );
	}

	return( avl_list[ avl_nextlist++ ] );
}

/* end non-reentrant code */


int
avl_dup_error( void* left, void* right )
{
	return( -1 );
}

int
avl_dup_ok( void* left, void* right )
{
	return( 0 );
}

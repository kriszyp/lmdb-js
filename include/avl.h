/* avl.h - avl tree definitions */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
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


#ifndef _AVL
#define _AVL

#include <ldap_cdefs.h>

/*
 * this structure represents a generic avl tree node.
 */

LDAP_BEGIN_DECL

typedef struct avlnode Avlnode;

#ifdef AVL_INTERNAL
struct avlnode {
	void*		avl_data;
	signed int		avl_bf;
	struct avlnode	*avl_left;
	struct avlnode	*avl_right;
};

#define NULLAVL	((Avlnode *) NULL)

/* balance factor values */
#define LH 	(-1)
#define EH 	0
#define RH 	1

/* avl routines */
#define avl_getone(x)	((x) == 0 ? 0 : (x)->avl_data)
#define avl_onenode(x)	((x) == 0 || ((x)->avl_left == 0 && (x)->avl_right == 0))

#endif /* AVL_INTERNALS */

typedef int		(*AVL_APPLY) LDAP_P((void *, void*));
typedef int		(*AVL_CMP) LDAP_P((const void*, const void*));
typedef int		(*AVL_DUP) LDAP_P((void*, void*));
typedef void	(*AVL_FREE) LDAP_P((void*));

LDAP_AVL_F( int )
avl_free LDAP_P(( Avlnode *root, AVL_FREE dfree ));

LDAP_AVL_F( int )
avl_insert LDAP_P((Avlnode **, void*, AVL_CMP, AVL_DUP));

LDAP_AVL_F( void* )
avl_delete LDAP_P((Avlnode **, void*, AVL_CMP));

LDAP_AVL_F( void* )
avl_find LDAP_P((Avlnode *, const void*, AVL_CMP));

LDAP_AVL_F( void* )
avl_find_lin LDAP_P((Avlnode *, const void*, AVL_CMP));

#ifdef AVL_NONREENTRANT
LDAP_AVL_F( void* )
avl_getfirst LDAP_P((Avlnode *));

LDAP_AVL_F( void* )
avl_getnext LDAP_P((void));
#endif

LDAP_AVL_F( int )
avl_dup_error LDAP_P((void*, void*));

LDAP_AVL_F( int )
avl_dup_ok LDAP_P((void*, void*));

LDAP_AVL_F( int )
avl_apply LDAP_P((Avlnode *, AVL_APPLY, void*, int, int));

LDAP_AVL_F( int )
avl_prefixapply LDAP_P((Avlnode *, void*, AVL_CMP, void*, AVL_CMP, void*, int));

/* apply traversal types */
#define AVL_PREORDER	1
#define AVL_INORDER	2
#define AVL_POSTORDER	3
/* what apply returns if it ran out of nodes */
#define AVL_NOMORE	(-6)

LDAP_END_DECL

#endif /* _AVL */

/* avl.h - avl tree definitions */
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
 */


#ifndef _AVL
#define _AVL

#include <ldap_cdefs.h>

/*
 * this structure represents a generic avl tree node.
 */

LDAP_BEGIN_DECL

typedef struct avlnode {
	caddr_t		avl_data;
	signed char		avl_bf;
	struct avlnode	*avl_left;
	struct avlnode	*avl_right;
} Avlnode;

#define NULLAVL	((Avlnode *) NULL)

/* balance factor values */
#define LH 	-1
#define EH 	0
#define RH 	1

/* avl routines */
#define avl_getone(x)	((x) == 0 ? 0 : (x)->avl_data)
#define avl_onenode(x)	((x) == 0 || ((x)->avl_left == 0 && (x)->avl_right == 0))

/* looks like this function pointer is not used consistently */
/* typedef int	(*IFP)LDAP_P((caddr_t, caddr_t)); */
typedef int	(*IFP)();

LDAP_F int
avl_free LDAP_P(( Avlnode *root, IFP dfree ));

LDAP_F int
avl_insert LDAP_P((Avlnode **, caddr_t, IFP, IFP));

LDAP_F caddr_t
avl_delete LDAP_P((Avlnode **, caddr_t, IFP));

LDAP_F caddr_t
avl_find LDAP_P((Avlnode *, caddr_t, IFP));

LDAP_F caddr_t
avl_getfirst LDAP_P((Avlnode *));

#ifdef AVL_REENTRANT
LDAP_F caddr_t
avl_getnext LDAP_P((Avlnode *, caddr_t ));
#else
LDAP_F caddr_t
avl_getnext LDAP_P((void));
#endif

LDAP_F int
avl_dup_error LDAP_P((void));

LDAP_F int
avl_apply LDAP_P((Avlnode *, IFP, caddr_t, int, int));

/* apply traversal types */
#define AVL_PREORDER	1
#define AVL_INORDER	2
#define AVL_POSTORDER	3
/* what apply returns if it ran out of nodes */
#define AVL_NOMORE	-6

LDAP_END_DECL

#endif /* _AVL */

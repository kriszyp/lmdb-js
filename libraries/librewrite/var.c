/******************************************************************************
 *
 * Copyright (C) 2000 Pierangelo Masarati, <ando@sys-net.it>
 * All rights reserved.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users
 * ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 ******************************************************************************/

#include <portable.h>

#include "rewrite-int.h"

/*
 * Compares two vars
 */
static int
rewrite_var_cmp(
		const void *c1,
		const void *c2
)
{
	const struct rewrite_var *v1, *v2;

	v1 = ( struct rewrite_var * )c1;
	v2 = ( struct rewrite_var * )c2;
	
	assert( v1 != NULL );
	assert( v2 != NULL );
	assert( v1->lv_name != NULL );
	assert( v2->lv_name != NULL );

	return strcasecmp( v1->lv_name, v2->lv_name );
}

/*
 * Duplicate var ?
 */
static int
rewrite_var_dup(
		void *c1,
		void *c2
)
{
	struct rewrite_var *v1, *v2;

	v1 = ( struct rewrite_var * )c1;
	v2 = ( struct rewrite_var * )c2;

	assert( v1 != NULL );
	assert( v2 != NULL );
	assert( v1->lv_name != NULL );
	assert( v2->lv_name != NULL );

	return ( strcasecmp( v1->lv_name, v2->lv_name ) == 0 ? -1 : 0 );
}

/*
 * Finds a var
 */
struct rewrite_var *
rewrite_var_find(
		Avlnode *tree,
		const char *name
)
{
	struct rewrite_var var;

	assert( name != NULL );

	var.lv_name = ( char * )name;
	return ( struct rewrite_var * )avl_find( tree, 
			( caddr_t )&var, rewrite_var_cmp );
}

/*
 * Inserts a newly created var
 */
struct rewrite_var *
rewrite_var_insert(
		Avlnode **tree,
		const char *name,
		const char *value
)
{
	struct rewrite_var *var;
	int rc;

	assert( tree != NULL );
	assert( name != NULL );
	assert( value != NULL );
	
	var = calloc( sizeof( struct rewrite_var ), 1 );
	if ( var == NULL ) {
		return NULL;
	}
	var->lv_name = ( char * )strdup( name );
	if ( var->lv_name == NULL ) {
		free( var );
		return NULL;
	}
	var->lv_value.bv_val = strdup( value );
	if ( var->lv_value.bv_val == NULL ) {
		free( var );
		free( var->lv_name );
		return NULL;
	}
	var->lv_value.bv_len = strlen( value );
	rc = avl_insert( tree, ( caddr_t )var,
			rewrite_var_cmp, rewrite_var_dup );
	if ( rc != 0 ) { 
		free( var );
		free( var->lv_name );
		free( var->lv_value.bv_val );
		return NULL;
	}

	return var;
}

/*
 * Sets/inserts a var
 */
struct rewrite_var *
rewrite_var_set(
		Avlnode **tree,
		const char *name,
		const char *value,
		int insert
)
{
	struct rewrite_var *var;

	assert( tree != NULL );
	assert( name != NULL );
	assert( value != NULL );
	
	var = rewrite_var_find( *tree, name );
	if ( var == NULL ) {
		if ( insert ) {
			return rewrite_var_insert( tree, name, value );
		} else {
			return NULL;
		}
	} else {
		assert( var->lv_value.bv_val != NULL );

		free( var->lv_value.bv_val );
		var->lv_value.bv_val = ( char * )value;
		var->lv_value.bv_len = strlen( value );
	}

	return var;
}

/*
 * Frees a var
 */
static void 
rewrite_var_free(
                struct rewrite_var *var
)
{
	assert( var != NULL );

	assert( var->lv_name != NULL );
	assert( var->lv_value.bv_val != NULL );

	free( var->lv_name );
	free( var->lv_value.bv_val );
}

/*
 * Deletes a var tree
 */
int
rewrite_var_delete(
		Avlnode *tree
)
{
	avl_free( tree, ( AVL_FREE )rewrite_var_free );
	return REWRITE_SUCCESS;
}


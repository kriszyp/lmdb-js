/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENT:
 * This work was initially developed by Pierangelo Masarati for
 * inclusion in OpenLDAP Software.
 */

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

	v1 = ( const struct rewrite_var * )c1;
	v2 = ( const struct rewrite_var * )c2;
	
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
	memset( var, 0, sizeof( struct rewrite_var ) );
	var->lv_name = strdup( name );
	if ( var->lv_name == NULL ) {
		rc = -1;
		goto cleanup;
	}
	var->lv_value.bv_val = strdup( value );
	if ( var->lv_value.bv_val == NULL ) {
		rc = -1;
		goto cleanup;
	}
	var->lv_value.bv_len = strlen( value );
	rc = avl_insert( tree, ( caddr_t )var,
			rewrite_var_cmp, rewrite_var_dup );
	if ( rc != 0 ) { 
		rc = -1;
		goto cleanup;
	}

cleanup:;
	if ( rc != 0 ) {
		free( var->lv_name );
		free( var->lv_value.bv_val );
		free( var );
		var = NULL;
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
		var->lv_value.bv_val = strdup( value );
		var->lv_value.bv_len = strlen( value );
	}

	return var;
}

/*
 * Frees a var
 */
static void 
rewrite_var_free(
		void *v_var
)
{
	struct rewrite_var *var = v_var;
	assert( var != NULL );

	assert( var->lv_name != NULL );
	assert( var->lv_value.bv_val != NULL );

	free( var->lv_name );
	free( var->lv_value.bv_val );
	free( var );
}

/*
 * Deletes a var tree
 */
int
rewrite_var_delete(
		Avlnode *tree
)
{
	avl_free( tree, rewrite_var_free );
	return REWRITE_SUCCESS;
}


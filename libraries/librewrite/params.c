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
 * Defines and inits a variable with global scope
 */
int
rewrite_param_set(
		struct rewrite_info *info,
		const char *name,
		const char *value
)
{
	struct rewrite_var *var;

	assert( info != NULL );
	assert( name != NULL );
	assert( value != NULL );

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	var = rewrite_var_find( info->li_params, name );
	if ( var != NULL ) {
		assert( var->lv_value.bv_val != NULL );
		free( var->lv_value.bv_val );
		var->lv_value.bv_val = strdup( value );
		var->lv_value.bv_len = strlen( value );
	} else {
		var = rewrite_var_insert( &info->li_params, name, value );
		if ( var == NULL ) {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
			ldap_pvt_thread_rdwr_wunlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
			return REWRITE_ERR;
		}
	}	
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wunlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return REWRITE_SUCCESS;
}

/*
 * Gets a var with global scope
 */
int
rewrite_param_get(
		struct rewrite_info *info,
		const char *name,
		struct berval *value
)
{
	struct rewrite_var *var;

	assert( info != NULL );
	assert( name != NULL );
	assert( value != NULL );

	value->bv_val = NULL;
	value->bv_len = 0;
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_rlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	var = rewrite_var_find( info->li_params, name );
	if ( var == NULL ) {
		
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_rdwr_runlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
		
		return REWRITE_ERR;
	} else {
		value->bv_val = strdup( var->lv_value.bv_val );
		value->bv_len = var->lv_value.bv_len;
	}
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
        ldap_pvt_thread_rdwr_runlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	return REWRITE_SUCCESS;
}

/*
 * Destroys the parameter tree
 */
int
rewrite_param_destroy(
		struct rewrite_info *info
)
{
	int count;

	assert( info != NULL );
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	count = avl_free( info->li_params, NULL );
	info->li_params = NULL;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wunlock( &info->li_params_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return REWRITE_SUCCESS;
}


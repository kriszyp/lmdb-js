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
 * Compares two cookies
 */
static int
rewrite_cookie_cmp(
                const void *c1,
                const void *c2
)
{
	struct rewrite_session *s1, *s2;

	s1 = ( struct rewrite_session * )c1;
	s2 = ( struct rewrite_session * )c2;

	assert( s1 != NULL );
	assert( s2 != NULL );
	assert( s1->ls_cookie != NULL );
	assert( s2->ls_cookie != NULL );
	
        return ( ( s1->ls_cookie < s2->ls_cookie ) ? -1 :
			( ( s1->ls_cookie > s2->ls_cookie ) ? 1 : 0 ) );
}

/*
 * Duplicate cookies?
 */
static int
rewrite_cookie_dup(
                void *c1,
                void *c2
)
{
	struct rewrite_session *s1, *s2;

	s1 = ( struct rewrite_session * )c1;
	s2 = ( struct rewrite_session * )c2;
	
	assert( s1 != NULL );
	assert( s2 != NULL );
	assert( s1->ls_cookie != NULL );
	assert( s2->ls_cookie != NULL );
	
        return ( ( s1->ls_cookie == s2->ls_cookie ) ? -1 : 0 );
}

/*
 * Inits a session
 */
struct rewrite_session *
rewrite_session_init(
		struct rewrite_info *info,
		const void *cookie
)
{
	struct rewrite_session *session;
	int rc;

	assert( info != NULL );
	assert( cookie != NULL );
	
	session = calloc( sizeof( struct rewrite_session ), 1 );
	if ( session == NULL ) {
		return NULL;
	}
	session->ls_cookie = ( void * )cookie;
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	if ( ldap_pvt_thread_rdwr_init( &session->ls_vars_mutex ) ) {
		free( session );
		return NULL;
	}
	ldap_pvt_thread_rdwr_wlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	rc = avl_insert( &info->li_cookies, ( caddr_t )session,
			rewrite_cookie_cmp, rewrite_cookie_dup );
	info->li_num_cookies++;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
        ldap_pvt_thread_rdwr_wunlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	if ( rc != 0 ) {
		free( session );
		return NULL;
	}
	
	return session;
}

/*
 * Fetches a session
 */
struct rewrite_session *
rewrite_session_find(
		struct rewrite_info *info,
		const void *cookie
)
{
	struct rewrite_session *session, tmp;

	assert( info != NULL );
	assert( cookie != NULL );
	
	tmp.ls_cookie = ( void * )cookie;
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_rlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	session = ( struct rewrite_session * )avl_find( info->li_cookies,
			( caddr_t )&tmp, rewrite_cookie_cmp );
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_runlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return session;
		
}

/*
 * Defines and inits a var with session scope
 */
int
rewrite_session_var_set(
		struct rewrite_info *info,
		const void *cookie,
		const char *name,
		const char *value
)
{
	struct rewrite_session *session;
	struct rewrite_var *var;

	assert( info != NULL );
	assert( cookie != NULL );
	assert( name != NULL );
	assert( value != NULL );

	session = rewrite_session_find( info, cookie );
	if ( session == NULL ) {
		session = rewrite_session_init( info, cookie );
	}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	var = rewrite_var_find( session->ls_vars, name );
	if ( var != NULL ) {
		assert( var->lv_value.bv_val != NULL );
		free( var->lv_value.bv_val );
		var->lv_value.bv_val = strdup( value );
		var->lv_value.bv_len = strlen( value );
	} else {
		var = rewrite_var_insert( &session->ls_vars, name, value );
		if ( var == NULL ) {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
			ldap_pvt_thread_rdwr_wunlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
			return REWRITE_ERR;
		}
	}	
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wunlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return REWRITE_SUCCESS;
}

/*
 * Gets a var with session scope
 */
int
rewrite_session_var_get(
		struct rewrite_info *info,
		const void *cookie,
		const char *name,
		struct berval *value
)
{
	struct rewrite_session *session;
	struct rewrite_var *var;

	assert( info != NULL );
	assert( cookie != NULL );
	assert( name != NULL );
	assert( value != NULL );

	value->bv_val = NULL;
	value->bv_len = 0;
	
	if ( cookie == NULL ) {
		return REWRITE_ERR;
	}

	session = rewrite_session_find( info, cookie );
	if ( session == NULL ) {
		return REWRITE_ERR;
	}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_rlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	var = rewrite_var_find( session->ls_vars, name );
	if ( var == NULL ) {
		
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	        ldap_pvt_thread_rdwr_runlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
		
		return REWRITE_ERR;
	} else {
		value->bv_val = strdup( var->lv_value.bv_val );
		value->bv_len = var->lv_value.bv_len;
	}
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
        ldap_pvt_thread_rdwr_runlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	
	return REWRITE_SUCCESS;
}

/*
 * Deletes a session
 */
int
rewrite_session_delete(
		struct rewrite_info *info,
		const void *cookie
)
{
	struct rewrite_session *session, tmp;

	assert( info != NULL );
	assert( cookie != NULL );

	tmp.ls_cookie = ( void * )cookie;
	
	session = rewrite_session_find( info, cookie );

	if ( session != NULL ) {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_rdwr_wlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
		rewrite_var_delete( session->ls_vars );
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_rdwr_wunlock( &session->ls_vars_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	assert( info->li_num_cookies > 0 );
	info->li_num_cookies--;
	
	/*
	 * There is nothing to delete in the return value
	 */
	avl_delete( &info->li_cookies, ( caddr_t )&tmp, rewrite_cookie_cmp );
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wunlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return REWRITE_SUCCESS;
}

/*
 * Destroys the cookie tree
 */
int
rewrite_session_destroy(
		struct rewrite_info *info
)
{
	int count;

	assert( info != NULL );
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	/*
	 * Should call per-session destruction routine ...
	 */
	
	count = avl_free( info->li_cookies, NULL );
	info->li_cookies = NULL;
	assert( count == info->li_num_cookies );
	info->li_num_cookies = 0;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_rdwr_wunlock( &info->li_cookies_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

	return REWRITE_SUCCESS;
}


/* $OpenLDAP$/
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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
/* (C) Copyright PADL Software Pty Ltd. 2003
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that this notice is preserved
 * and that due credit is given to PADL Software Pty Ltd. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Luke Howard for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <ac/string.h>
#include <ac/stdarg.h>
#include <ac/ctype.h>
#include <ac/unistd.h>
#include <ldap_pvt.h>

#include <slap.h>
#include <slapi.h>

#ifdef LDAP_SLAPI
/*
 * Object extensions
 *
 * We only support two types -- connection and operation extensions.
 * Define more types in slapi.h
 */

/* global state */
struct slapi_registered_extension_set {
	ldap_pvt_thread_mutex_t mutex;
	struct slapi_registered_extension {
		int active;
		int count;
		slapi_extension_constructor_fnptr *constructors;
		slapi_extension_destructor_fnptr *destructors;
	} extensions[SLAPI_X_EXT_MAX];
} registered_extensions;

/* per-object state */
struct slapi_extension_block {
	void **extensions;
};

static int getExtensionBlock(int objecttype, void *object, struct slapi_extension_block **eblock, void **parent)
{
	switch ((slapi_extension_t) objecttype) {
	case SLAPI_X_EXT_CONNECTION:
		*eblock = ((Connection *)object)->c_extensions;
		*parent = NULL;
		break;	
	case SLAPI_X_EXT_OPERATION:
		*eblock = ((Operation *)object)->o_extensions;
		*parent = ((Operation *)object)->o_conn;
		break;	
	default:
		return -1;
		break;
	}

	if ( *eblock == NULL ) {
		return -1;
	}

	return 0;
}

static int mapExtensionType(const char *objectname, slapi_extension_t *type)
{
	if ( strcasecmp( objectname, SLAPI_EXT_CONNECTION ) == 0 ) {
		*type = SLAPI_X_EXT_CONNECTION;
	} else if ( strcasecmp( objectname, SLAPI_EXT_OPERATION ) == 0 ) {
		*type = SLAPI_X_EXT_OPERATION;
	} else {
		return -1;
	}

	return 0;
}

static void newExtension(struct slapi_extension_block *eblock, int objecttype, void *object, void *parent, int extensionhandle )
{
	slapi_extension_constructor_fnptr constructor;

	assert( objecttype < SLAPI_X_EXT_MAX );
	assert( extensionhandle < registered_extensions.extensions[objecttype].count );

	assert( registered_extensions.extensions[objecttype].constructors != NULL );
	constructor = registered_extensions.extensions[objecttype].constructors[extensionhandle];

	assert( eblock->extensions[extensionhandle] == NULL );

	if ( constructor != NULL ) {
		eblock->extensions[extensionhandle] = (*constructor)( object, parent );
	} else {
		eblock->extensions[extensionhandle] = NULL;
	}
}

static void freeExtension(struct slapi_extension_block *eblock, int objecttype, void *object, void *parent, int extensionhandle )
{
	slapi_extension_destructor_fnptr destructor;

	assert( objecttype < SLAPI_X_EXT_MAX );
	assert( extensionhandle < registered_extensions.extensions[objecttype].count );

	if ( eblock->extensions[extensionhandle] != NULL ) {
		assert( registered_extensions.extensions[objecttype].destructors != NULL );
		destructor = registered_extensions.extensions[objecttype].destructors[extensionhandle];
		if ( destructor != NULL ) {
			(*destructor)( eblock->extensions[extensionhandle], object, parent );
		}
		eblock->extensions[extensionhandle] = NULL;
	}
}
#endif /* LDAP_SLAPI */

void *slapi_get_object_extension(int objecttype, void *object, int extensionhandle)
{
#ifdef LDAP_SLAPI
	struct slapi_extension_block *eblock;
	void *parent;

	if ( getExtensionBlock( objecttype, object, &eblock, &parent ) != 0 ) {
		return NULL;
	}

	if ( extensionhandle < registered_extensions.extensions[objecttype].count ) {
		return eblock->extensions[extensionhandle];
	}

	return NULL;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void slapi_set_object_extension(int objecttype, void *object, int extensionhandle, void *extension)
{
#ifdef LDAP_SLAPI
	struct slapi_extension_block *eblock;
	void *parent;

	if ( getExtensionBlock( objecttype, object, &eblock, &parent ) != 0 ) {
		return;
	}

	if ( extensionhandle < registered_extensions.extensions[objecttype].count ) {
		/* free the old one */
		freeExtension( eblock, objecttype, object, parent, extensionhandle );

		/* constructed by caller */
		eblock->extensions[extensionhandle] = extension;
	}
#endif /* LDAP_SLAPI */
}

int slapi_register_object_extension(
	const char *pluginname,
	const char *objectname,
	slapi_extension_constructor_fnptr constructor,
	slapi_extension_destructor_fnptr destructor,
	int *objecttype,
	int *extensionhandle)
{
#ifdef LDAP_SLAPI
	int rc;
	slapi_extension_t type;
	struct slapi_registered_extension *re;

	ldap_pvt_thread_mutex_lock( &registered_extensions.mutex );

	rc = mapExtensionType( objectname, &type );
	if ( rc != 0 ) {
		ldap_pvt_thread_mutex_unlock( &registered_extensions.mutex );
		return rc;
	}

	*objecttype = (int)type;

	re = &registered_extensions.extensions[*objecttype];

	*extensionhandle = re->count;

	if ( re->active ) {
		/* can't add new extensions after objects have been created */
		ldap_pvt_thread_mutex_unlock( &registered_extensions.mutex );
		return -1;
	}

	re->count++;

	if ( re->constructors == NULL ) {
		re->constructors = (slapi_extension_constructor_fnptr *)slapi_ch_calloc( re->count,
			sizeof( slapi_extension_constructor_fnptr ) );
	} else {
		re->constructors = (slapi_extension_constructor_fnptr *)slapi_ch_realloc( (char *)re->constructors,
			re->count * sizeof( slapi_extension_constructor_fnptr ) );
	}
	re->constructors[*extensionhandle] = constructor;

	if ( re->destructors == NULL ) {
		re->destructors = (slapi_extension_destructor_fnptr *)slapi_ch_calloc( re->count,
			sizeof( slapi_extension_destructor_fnptr ) );
	} else {
		re->destructors = (slapi_extension_destructor_fnptr *)slapi_ch_realloc( (char *)re->destructors,
			re->count * sizeof( slapi_extension_destructor_fnptr ) );
	}
	re->destructors[*extensionhandle] = destructor;

	ldap_pvt_thread_mutex_unlock( &registered_extensions.mutex );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int slapi_x_create_object_extensions(int objecttype, void *object)
{
#ifdef LDAP_SLAPI
	int i, rc;
	struct slapi_extension_block *eblock;
	void **peblock;
	void *parent;

	switch ((slapi_extension_t) objecttype) {
	case SLAPI_X_EXT_CONNECTION:
		peblock = &(((Connection *)object)->c_extensions);
		parent = NULL;
		break;	
	case SLAPI_X_EXT_OPERATION:
		peblock = &(((Operation *)object)->o_extensions);
		parent = ((Operation *)object)->o_conn;
		break;
	default:
		return -1;
		break;
	}

	*peblock = NULL;

	ldap_pvt_thread_mutex_lock( &registered_extensions.mutex );
	if ( registered_extensions.extensions[objecttype].active == 0 ) {
		/*
		 * once we've created some extensions, no new extensions can
		 * be registered.
		 */
		registered_extensions.extensions[objecttype].active = 1;
	}
	ldap_pvt_thread_mutex_unlock( &registered_extensions.mutex );

	eblock = (struct slapi_extension_block *)slapi_ch_calloc( 1, sizeof(*eblock) );

	if ( registered_extensions.extensions[objecttype].count ) {
		eblock->extensions = (void **)slapi_ch_calloc( registered_extensions.extensions[objecttype].count, sizeof(void *) );
		for ( i = 0; i < registered_extensions.extensions[objecttype].count; i++ ) {
			newExtension( eblock, objecttype, object, parent, i );
		}
	} else {
		eblock->extensions = NULL;
	}

	*peblock = eblock;

	return 0;
#else
	return -1;
#endif
}

int slapi_x_free_object_extensions(int objecttype, void *object)
{
#ifdef LDAP_SLAPI
	int i, rc;
	struct slapi_extension_block *eblock;
	void **peblock;
	void *parent;

	switch ((slapi_extension_t) objecttype) {
	case SLAPI_X_EXT_CONNECTION:
		peblock = &(((Connection *)object)->c_extensions);
		parent = NULL;
		break;	
	case SLAPI_X_EXT_OPERATION:
		peblock = &(((Operation *)object)->o_extensions);
		parent = ((Operation *)object)->o_conn;
		break;	
	default:
		return -1;
		break;
	}

	eblock = (struct slapi_extension_block *)*peblock;

	if ( eblock->extensions != NULL ) {
		for ( i = registered_extensions.extensions[objecttype].count - 1; i >= 0; --i ) {
			freeExtension( eblock, objecttype, object, parent, i );
		}

		slapi_ch_free( (void **)&eblock->extensions );
	}

	slapi_ch_free( peblock );

	return 0;
#else
	return -1;
#endif
}

/* for reusable object types */
int slapi_x_clear_object_extensions(int objecttype, void *object)
{
#ifdef LDAP_SLAPI
	int i, rc;
	struct slapi_extension_block *eblock;
	void *parent;

	if ( getExtensionBlock( objecttype, object, &eblock, &parent ) != 0 ) {
		return -1;
	}

	if ( eblock->extensions == NULL ) {
		/* no extensions */
		return 0;
	}

	for ( i = registered_extensions.extensions[objecttype].count - 1; i >= 0; --i ) {
		freeExtension( eblock, objecttype, object, parent, i );
	}

	for ( i = 0; i < registered_extensions.extensions[objecttype].count; i++ ) {
		newExtension( eblock, objecttype, object, parent, i );
	}

	return 0;
#else
	return -1;
#endif
}

int slapi_x_init_object_extensions(void)
{
#ifdef LDAP_SLAPI
	memset( &registered_extensions, 0, sizeof( registered_extensions ) );

	if ( ldap_pvt_thread_mutex_init( &registered_extensions.mutex ) != 0 ) {
		return -1;
	}

	return 0;
#else
	return -1;
#endif
}

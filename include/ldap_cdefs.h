/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/* LDAP C Defines */

#ifndef _LDAP_CDEFS_H
#define _LDAP_CDEFS_H

#if defined(__cplusplus) || defined(c_plusplus)
#	define LDAP_BEGIN_DECL	extern "C" {
#	define LDAP_END_DECL	}
#else
#	define LDAP_BEGIN_DECL	/* begin declarations */
#	define LDAP_END_DECL	/* end declarations */
#endif

#if !defined(__NO_PROTOTYPES) && ( defined(__NEED_PROTOTYPES) || \
	defined(__STDC__) || defined(__cplusplus) || defined(c_plusplus) )

	/* ANSI C or C++ */
#	define LDAP_P(protos)	protos
#	define LDAP_CONCAT1(x,y)	x ## y
#	define LDAP_CONCAT(x,y)	LDAP_CONCAT1(x,y)
#	define LDAP_STRING(x)	#x /* stringify without expanding x */
#	define LDAP_XSTRING(x)	LDAP_STRING(x) /* expand x, then stringify */

#ifndef LDAP_CONST
#	define LDAP_CONST	const
#endif

#else /* no prototypes */

	/* traditional C */
#	define LDAP_P(protos)	()
#	define LDAP_CONCAT(x,y)	x/**/y
#	define LDAP_STRING(x)	"x"

#ifndef LDAP_CONST
#	define LDAP_CONST	/* no const */
#endif

#endif /* no prototypes */

#if _WIN32 && _DLL
#	define LDAP_F_IMPORT	extern __declspec( dllimport )
#	define LDAP_F_EXPORT	extern __declspec( dllexport )
#else
#	define LDAP_F_IMPORT	extern
#	define LDAP_F_EXPORT	extern
#endif

#if (__GNUC__) * 1000 + (__GNUC_MINOR__) >= 2006
#	define LDAP_GCCATTR(attrs)	__attribute__(attrs)
#else
#	define LDAP_GCCATTR(attrs)
#endif

/* Proper support for NT dynamic libraries. */

/*
 * C library. Mingw32 links with the C run-time library by default,
 * so the explicit definition of CSTATIC will keep dllimport from
 * being defined.
 */
#if (defined(__MINGW32__) && !defined(CSTATIC) || \
     defined(_WIN32) && defined(_DLL))
#	define LIBC_F(type)	extern __declspec(dllimport) type
#else
#	define LIBC_F(type)	extern type
#endif

/* AVL library */
#if defined(LIBAVL_DECL) && defined(_WIN32)
#	define LIBAVL_F(type)	extern __declspec(LIBAVL_DECL) type
#else
#	define LIBAVL_F(type)	extern type
#endif

/* LBER library */
#if defined(LIBLBER_DECL) && defined(_WIN32)
#	define LIBLBER_F(type)	extern __declspec(LIBLBER_DECL) type
#else
#	define LIBLBER_F(type)	extern type
#endif

/* LDAP library */
#if defined(LIBLDAP_DECL) && defined(_WIN32)
#	define LIBLDAP_F(type)	extern __declspec(LIBLDAP_DECL) type
#else
#	define LIBLDAP_F(type)	extern type
#endif

/* LDBM library */
#if defined(LIBLDBM_DECL) && defined(_WIN32)
#	define LIBLDBM_F(type)	extern __declspec(LIBLDBM_DECL) type
#else
#	define LIBLDBM_F(type)	extern type
#endif

/* LDIF library */
#if defined(LIBLDIF_DECL) && defined(_WIN32)
#	define LIBLDIF_F(type)	extern __declspec(LIBLDIF_DECL) type
#else
#	define LIBLDIF_F(type)	extern type
#endif

/* LUTIL library */
#if defined(LIBLUTIL_DECL) && defined(_WIN32)
#	define LIBLUTIL_F(type)	extern __declspec(LIBLUTIL_DECL) type
#else
#	define LIBLUTIL_F(type)	extern type
#endif

/* SLAPD (as a module exporting symbols) */
#if defined(LIBSLAPD_DECL) && defined(_WIN32)
#	define LIBSLAPD_F(type)	extern __declspec(LIBSLAPD_DECL) type
#else
#	define LIBSLAPD_F(type)	extern type
#endif

#endif /* _LDAP_CDEFS_H */

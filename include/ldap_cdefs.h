/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
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

#if !defined(LDAP_NO_PROTOTYPES) && ( defined(LDAP_NEEDS_PROTOTYPES) || \
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

#if (__GNUC__) * 1000 + (__GNUC_MINOR__) >= 2006
#	define LDAP_GCCATTR(attrs)	__attribute__(attrs)
#else
#	define LDAP_GCCATTR(attrs)
#endif


/* Support for NT dynamic libraries. */

/* LBER library */
#if defined(LBER_DECL) && defined(_WIN32)
#	define LBER_F(type)		extern __declspec(LBER_DECL) type
#	define LBER_V(type)		extern __declspec(LBER_DECL) type
#else
#	define LBER_F(type)		extern type
#	define LBER_V(type)		extern type
#endif

/* LDAP library */
#if defined(LDAP_DECL) && defined(_WIN32)
#	define LDAP_F(type)		extern __declspec(LDAP_DECL) type
#	define LDAP_V(type)		extern __declspec(LDAP_DECL) type
#else
#	define LDAP_F(type)		extern type
#	define LDAP_V(type)		extern type
#endif

/*
 * C library. Mingw32 links with the C run-time library by default,
 * so the explicit definition of CSTATIC will keep dllimport from
 * being defined.
 */
#if (defined(__MINGW32__) && !defined(CSTATIC) || \
     defined(_WIN32) && defined(_DLL))
#	define LDAP_LIBC_F(type)	extern __declspec(dllimport) type
#	define LDAP_LIBC_V(type)	extern __declspec(dllimport) type
#else
#	define LDAP_LIBC_F(type)	extern type
#	define LDAP_LIBC_V(type)	extern type
#endif

/* AVL library */
#if defined(LDAP_AVL_DECL) && defined(_WIN32)
#	define LDAP_AVL_F(type)	extern __declspec(LDAP_AVL_DECL) type
#	define LDAP_AVL_V(type)	extern __declspec(LDAP_AVL_DECL) type
#else
#	define LDAP_AVL_F(type)	extern type
#	define LDAP_AVL_V(type)	extern type
#endif

/* LDBM library */
#if defined(LDAP_LDBM_DECL) && defined(_WIN32)
#	define LDAP_LDBM_F(type)	extern __declspec(LDAP_LDBM_DECL) type
#	define LDAP_LDBM_V(type)	extern __declspec(LDAP_LDBM_DECL) type
#else
#	define LDAP_LDBM_F(type)	extern type
#	define LDAP_LDBM_V(type)	extern type
#endif

/* LDIF library */
#if defined(LDAP_LDIF_DECL) && defined(_WIN32)
#	define LDAP_LDIF_F(type)	extern __declspec(LDAP_LDIF_DECL) type
#	define LDAP_LDIF_V(type)	extern __declspec(LDAP_LDIF_DECL) type
#else
#	define LDAP_LDIF_F(type)	extern type
#	define LDAP_LDIF_V(type)	extern type
#endif

/* LUNICODE library */
#if defined(LDAP_LUNICODE_DECL) && defined(_WIN32)
#	define LDAP_LUNICODE_F(type)	extern __declspec(LDAP_LUNICODE_DECL) type
#	define LDAP_LUNICODE_V(type)	extern __declspec(LDAP_LUNICODE_DECL) type
#else
#	define LDAP_LUNICODE_F(type)	extern type
#	define LDAP_LUNICODE_V(type)	extern type
#endif

/* LUTIL library */
#if defined(LDAP_LUTIL_DECL) && defined(_WIN32)
#	define LDAP_LUTIL_F(type)	extern __declspec(LDAP_LUTIL_DECL) type
#	define LDAP_LUTIL_V(type)	extern __declspec(LDAP_LUTIL_DECL) type
#else
#	define LDAP_LUTIL_F(type)	extern type
#	define LDAP_LUTIL_V(type)	extern type
#endif

/* SLAPD (as a module exporting symbols) */
#if defined(LDAP_SLAPD_DECL) && defined(_WIN32)
#	define LDAP_SLAPD_F(type)	extern __declspec(LDAP_SLAPD_DECL) type
#	define LDAP_SLAPD_V(type)	extern __declspec(LDAP_SLAPD_DECL) type
#else
#	define LDAP_SLAPD_F(type)	extern type
#	define LDAP_SLAPD_V(type)	extern type
#endif

#endif /* _LDAP_CDEFS_H */

/* LDAP C Defines */

#ifndef _LDAP_CDEFS_H
#define _LDAP_CDEFS_H

#if defined(__cplusplus)
#	define LDAP_BEGIN_DECL	extern "C" {
#	define LDAP_END_DECL	}
#else
#	define LDAP_BEGIN_DECL	/* begin declarations */
#	define LDAP_END_DECL	/* end declarations */
#endif

#if !defined(__NO_PROTOTYPES) && ( \
	defined(__STDC__) || defined(__cplusplus) || \
	defined(__NEED_PROTOTYPES) )

	/* ANSI C or C++ */
#	define LDAP_P(protos)	protos
#	define LDAP_CONCAT1(x,y)	x ## y
#	define LDAP_CONCAT(x,y)	LDAP_CONCAT1(x,y)
#	define LDAP_STRING(x)	#x /* stringify without expanding x */
#	define LDAP_XSTRING(x)	LDAP_STRING(x) /* expand x, then stringify */

#else /* no prototypes */

	/* traditional C */
#	define LDAP_P(protos)	()
#	define LDAP_CONCAT(x,y)	x/**/y
#	define LDAP_STRING(x)	"x"

#endif /* no prototypes */


#ifndef LDAP_F
#	ifdef _WIN32
#		define LDAP_F	__declspec( dllexport )
#	else /* ! _WIN32 */
#		define LDAP_F	extern
#	endif /* _WIN32 */
#endif /* LDAP_FDECL */

#endif /* _LDAP_CDEFS_H */

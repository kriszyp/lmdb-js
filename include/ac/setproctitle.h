/* Generic setproctitle.h */

#ifndef _AC_SETPROCTITLE_H
#define _AC_SETPROCTITLE_H

#ifdef LDAP_PROCTITLE

#if defined( HAVE_LIBUTIL_H )
#	include <libutil.h>
#else
	/* use lutil version */
	void setproctitle LDAP_P((const char *fmt, ...));
	extern int Argc;
	extern char **Argv;
#endif

#endif /* LDAP_PROCTITLE */
#endif /* _AC_SETPROCTITLE_H */

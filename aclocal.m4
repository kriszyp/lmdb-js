dnl --------------------------------------------------------------------
dnl Restricted form of AC_ARG_ENABLE that ensures user doesn't give bogus
dnl values.
dnl
dnl Parameters:
dnl $1 = option name
dnl $2 = help-string
dnl $3 = action to perform if option is not default
dnl $4 = action if perform if option is default
dnl $5 = default option value (either 'yes' or 'no')
AC_DEFUN([CF_ARG_OPTION],
[AC_ARG_ENABLE($1,[$2],[test "$enableval" != ifelse($5,no,yes,no) && enableval=ifelse($5,no,no,yes)
  if test "$enableval" != "$5" ; then
ifelse($3,,[    :]dnl
,[    $3]) ifelse($4,,,[
  else
    $4])
  fi],[enableval=$5 ifelse($4,,,[
  $4
])dnl
  ])])dnl
dnl --------------------------------------------------------------------
dnl Check for declaration of sys_errlist in one of stdio.h and errno.h.
dnl Declaration of sys_errlist on BSD4.4 interferes with our declaration.
dnl Reported by Keith Bostic.
AC_DEFUN([CF_SYS_ERRLIST],
[
AC_MSG_CHECKING([declaration of sys_errlist])
AC_CACHE_VAL(cf_cv_dcl_sys_errlist,[
	AC_TRY_COMPILE([
#include <stdio.h>
#include <sys/types.h>
#include <errno.h> ],
	[char *c = (char *) *sys_errlist],
	[cf_cv_dcl_sys_errlist=yes],
	[cf_cv_dcl_sys_errlist=no])])
AC_MSG_RESULT($cf_cv_dcl_sys_errlist)

# It's possible (for near-UNIX clones) that sys_errlist doesn't exist
if test $cf_cv_dcl_sys_errlist = no ; then
	AC_DEFINE(DECL_SYS_ERRLIST)
	AC_MSG_CHECKING([existence of sys_errlist])
	AC_CACHE_VAL(cf_cv_have_sys_errlist,[
		AC_TRY_LINK([#include <errno.h>],
			[char *c = (char *) *sys_errlist],
			[cf_cv_have_sys_errlist=yes],
			[cf_cv_have_sys_errlist=no])])
	AC_MSG_RESULT($cf_cv_have_sys_errlist)
fi
])dnl

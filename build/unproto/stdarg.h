 /*
  * @(#) stdarg.h 1.4 93/06/18 22:29:44
  * 
  * Sample stdarg.h file for use with the unproto filter.
  * 
  * This file serves two purposes.
  * 
  * 1 - On systems that do not have a /usr/include/stdarg.h file, it should be
  * included by C source files that implement ANSI-style variadic functions.
  * Ultrix 4.[0-2] comes with stdarg.h but still needs the one that is
  * provided with the unproto filter.
  * 
  * 2 - To configure the unprototyper itself. If the _VA_ALIST_ macro is
  * defined, its value will appear in the place of the "..." at the end of
  * argument lists of variadic function *definitions* (not declarations).
  * Some compilers (such as Greenhills m88k) have a non-empty va_dcl
  * definition in the system header file varargs.h. If that is the case,
  * define "_VA_DCL_" with the same value as va_dcl. If _VA_DCL_ is defined,
  * the unprototyper will emit its value just before the opening "{".
  * 
  * Compilers that always pass arguments via the stack can use the default code
  * at the end of this file (this usually applies for the vax, mc68k and
  * 80*86 architectures).
  * 
  * Special tricks are needed for compilers that pass some or all function
  * arguments via registers. Examples of the latter are given for the mips
  * and sparc architectures. Usually the compiler special-cases an argument
  * declaration such as "va_alist" or "__builtin_va_alist". For inspiration,
  * see the local /usr/include/varargs.h file.
  * 
  * You can use the varargs.c program provided with the unproto package to
  * verify that the stdarg.h file has been set up correctly.
  */

#ifdef sparc /* tested with SunOS 4.1.1 */

#define _VA_ALIST_		"__builtin_va_alist"
typedef char *va_list;
#define va_start(ap, p)		(ap = (char *) &__builtin_va_alist)
#define va_arg(ap, type)	((type *) __builtin_va_arg_incr((type *) ap))[0]
#define va_end(ap)

#else
#ifdef mips /* tested with Ultrix 4.0 and 4.2 */

#define _VA_ALIST_		"va_alist"
#include "/usr/include/stdarg.h"

#else
#ifdef m88k /* Motorola SYSTEM V/88 R32V3 */

#define _VA_ALIST_		"va_alist"
#define _VA_DCL_		"va_type va_alist;"
typedef struct _va_struct {
    int va_narg;
    int *va_stkaddr;
    int *va_iregs;
} va_list;
#define va_start(ap, p) \
((ap).va_narg=(int *)&va_alist-va_stkarg, \
 (ap).va_stkaddr=va_stkarg, \
 (ap).va_iregs=(int *)va_intreg)
#define va_end(p)
#if defined(LittleEndian)
#define va_arg(p,mode) \
    (*(mode *)_gh_va_arg(&p, va_align(mode), va_regtyp(mode), sizeof(mode)))
#else /* defined(LittleEndian) */
#define va_arg(p,mode) ( \
    (p).va_narg += ((p).va_narg & (va_align(mode) == 8)) + \
                      (sizeof(mode)+3)/4, \
    ((mode *)((va_regtyp(mode) && (p).va_narg <= 8 ? \
             (p).va_iregs: \
             (p).va_stkaddr) + (p).va_narg))[-1])
#endif /* defined(LittleEndian) */

#else
#ifdef hpux
#include <stdarg.h>

#else /* vax, mc68k, 80*86 */

typedef char *va_list;
#define va_start(ap, p)		(ap = (char *) (&(p)+1))
#define va_arg(ap, type)	((type *) (ap += sizeof(type)))[-1]
#define va_end(ap)

#endif /* hpux */
#endif /* m88k */
#endif /* mips */
#endif /* sparc */

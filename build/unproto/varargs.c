 /*
  * @(#) varargs.c 1.1 91/09/01 23:08:45
  * 
  * This program can be used to verify that the stdarg.h file is set up
  * correctly for your system. If it works, it should print one line with the
  * text "stdarg.h works".
  */

#include <stdio.h>
#include "stdarg.h"

main(int argc, char *argv[])
{
    varargs_test("%s %s\n", "stdarg.h", "works");
}

varargs_test(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    while (*fmt) {
	if (strncmp("%s", fmt, 2) == 0) {
	    fputs(va_arg(ap, char *), stdout);
	    fmt += 2;
	} else {
	    putchar(*fmt);
	    fmt++;
	}
    }
    va_end(ap);
}

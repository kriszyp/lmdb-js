#include <stdio.h>
#include <stdarg.h>

int debug(const char *format,...) {
#ifdef DEBUG
	va_list args;
	int ret;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
#endif
}

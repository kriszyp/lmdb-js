#include <stdio.h>
#include <stdarg.h>

extern int debug_level;

int debug(const char *format,...) {
	if (debug_level > 0) {
//#ifdef DEBUG
		va_list args;
		int ret;
		va_start(args, format);
		ret = vprintf(format, args);
		va_end(args);
		return ret;
//#endif
	}
}

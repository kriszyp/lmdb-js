#include <windows.h>
#include <winerror.h>

char *GetErrorString( int err )
{
	static char msgBuf[1024];

	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		msgBuf, 1024, NULL );
	return msgBuf;
}

char *GetLastErrorString( void )
{
	return GetErrorString( GetLastError() );
}

#undef __RETSTR

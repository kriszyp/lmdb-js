/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"
#include <stdio.h>
#include <ac/string.h>
#include "slap.h"

#ifdef HAVE_NT_SERVICE_MANAGER

/* in main.c */
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv );

/* in ntservice.c */
int srv_install( char* service, char * displayName, char* filename,
		 BOOL auto_start );
int srv_remove ( char* service, char* filename );

int main( int argc, LPTSTR *argv )
{
	int		length;
	char	filename[MAX_PATH], *fname_start;
	extern int is_NT_Service;

	/*
	 * Because the service was registered as SERVICE_WIN32_OWN_PROCESS,
	 * the lpServiceName element of the SERVICE_TABLE_ENTRY will be
	 * ignored. Since we don't even know the name of the service at
	 * this point (since it could have been installed under a name
	 * different than SERVICE_NAME), we might as well just provide
	 * the parameter as "".
	 */

	SERVICE_TABLE_ENTRY		DispatchTable[] = {
		{	"",	(LPSERVICE_MAIN_FUNCTION) ServiceMain	},
		{	NULL,			NULL	}
	};

	/*
	// set the service's current directory to being the installation directory for the service.
	// this way we don't have to write absolute paths in the configuration files
	*/
	GetModuleFileName( NULL, filename, sizeof( filename ) );
	fname_start = strrchr( filename, *LDAP_DIRSEP );
	*fname_start = '\0';
	SetCurrentDirectory( filename );

	if ( argc > 1 ) {
		if ( _stricmp( "install", argv[1] ) == 0 ) 
		{
			char *svcName = SERVICE_NAME;
			char *displayName = "OpenLDAP Directory Service";
			BOOL auto_start = FALSE;

			if ( (argc > 2) && (argv[2] != NULL) )
				svcName = argv[2];

			if ( argc > 3 && argv[3])
				displayName = argv[3];

			if ( argc > 4 && stricmp(argv[4], "auto") == 0)
				auto_start = TRUE;

			if ( (length = GetModuleFileName(NULL, filename, sizeof( filename ))) == 0 ) 
			{
				fputs( "unable to retrieve file name for the service.\n", stderr  );
				return EXIT_FAILURE;
			}
			if ( !srv_install(svcName, displayName, filename, auto_start) ) 
			{
				fputs( "service failed installation ...\n", stderr  );
				return EXIT_FAILURE;
			}
			fputs( "service has been installed ...\n", stderr  );
			return EXIT_SUCCESS;
		}

		if ( _stricmp( "remove", argv[1] ) == 0 ) 
		{
			char *svcName = SERVICE_NAME;
			if ( (argc > 2) && (argv[2] != NULL) )
				svcName = argv[2];
			if ( (length = GetModuleFileName(NULL, filename, sizeof( filename ))) == 0 ) 
			{
				fputs( "unable to retrieve file name for the service.\n", stderr  );
				return EXIT_FAILURE;
			}
			if ( !srv_remove(svcName, filename) ) 
			{
				fputs( "failed to remove the service ...\n", stderr  );
				return EXIT_FAILURE;
			}
			fputs( "service has been removed ...\n", stderr );
			return EXIT_SUCCESS;
		}
	}

	puts( "starting slapd..." );
	if ( !StartServiceCtrlDispatcher(DispatchTable) )
	{
		is_NT_Service = 0;
		ServiceMain( argc, argv );
	}

	return EXIT_SUCCESS;
}

#endif

// nt_main.c
#include "portable.h"
#include <stdio.h>

//#include <ac/signal.h>
//#include <ac/socket.h>
#include <ac/string.h>
//#include <ac/time.h>
//#include <ac/unistd.h>
//#include <ac/wait.h>
//#include <ac/signal.h>
//#include <ac/errno.h>

#include "ldap_defaults.h"
#include "slap.h"

/* kludge a path for now */
#include "../../libraries/liblutil/slapdmsg.h"

#define SCM_NOTIFICATION_INTERVAL	5000
#define THIRTY_SECONDS				(30 * 1000)

ldap_pvt_thread_cond_t	started_event,		stopped_event;
ldap_pvt_thread_t		start_status_tid,	stop_status_tid;


// in main.c
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv );


// in wsa_err.c
char *WSAGetLastErrorString( void );

// in nt_err.c
char *GetLastErrorString( void );

// in ntservice.c
int srv_install( char* service, char* filename );
int srv_remove ( char* service, char* filename );

void main( DWORD argc, LPTSTR *argv )
{
	int		length;
	char	filename[MAX_PATH], *fname_start;
	extern int is_NT_Service;

	SERVICE_TABLE_ENTRY		DispatchTable[] = {
		{	SERVICE_NAME,	(LPSERVICE_MAIN_FUNCTION) ServiceMain	},
		{	NULL,			NULL	}
	};

	// set the service's current directory to being the installation directory for the service.
	// this way we don't have to write absolute paths in the configuration files
	GetModuleFileName( NULL, filename, sizeof( filename ) );
	fname_start = strrchr( filename, *LDAP_DIRSEP );
	*fname_start = '\0';
	SetCurrentDirectory( filename );

	if ( argc > 1 ) {
		if ( _stricmp( "install", argv[1] ) == 0 ) 
		{
			char *svcName = SERVICE_NAME;
			if ( (argc > 2) && (argv[2] != NULL) )
				svcName = argv[2];
			if ( (length = GetModuleFileName(NULL, filename, sizeof( filename ))) == 0 ) 
			{
				fputs( "unable to retrieve file name for the service.\n", stderr  );
				return;
			}
			if ( !srv_install(svcName, filename) ) 
			{
				fputs( "service failed installation ...\n", stderr  );
				return;
			}
			fputs( "service has been installed ...\n", stderr  );
			return;
		}

		if ( _stricmp( "remove", argv[1] ) == 0 ) 
		{
			char *svcName = SERVICE_NAME;
			if ( (argc > 2) && (argv[2] != NULL) )
				svcName = argv[2];
			if ( (length = GetModuleFileName(NULL, filename, sizeof( filename ))) == 0 ) 
			{
				fputs( "unable to retrieve file name for the service.\n", stderr  );
				return;
			}
			if ( !srv_remove(svcName, filename) ) 
			{
				fputs( "failed to remove the service ...\n", stderr  );
				return;
			}
			fputs( "service has been removed ...\n", stderr );
			return;
		}
	}

	puts( "starting slapd..." );
	if ( !StartServiceCtrlDispatcher(DispatchTable) )
	{
		is_NT_Service = 0;
		ServiceMain( argc, argv );
	}
}

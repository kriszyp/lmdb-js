/* $OpenLDAP$ */

#include "portable.h"

#include <ldap.h>

static void stubs()
{
    ldap_add_s(NULL, NULL, NULL);
    ldap_bind_s(NULL, NULL, NULL, 0);
    ldap_delete_s(NULL, NULL);
    ldap_first_attribute(NULL, NULL, NULL);
    ldap_first_entry(NULL, NULL);
    ldap_get_dn(NULL, NULL);
    ldap_get_option(NULL, 0, NULL);
    ldap_get_values_len(NULL, NULL, NULL);
    ldap_init(NULL, 0);
    ldap_modify_s(NULL, NULL, NULL);
    ldap_modrdn_s(NULL, NULL, NULL);
    ldap_msgfree(NULL);
    ldap_next_attribute(NULL, NULL, NULL);
    ldap_result(NULL, 0, 0, NULL, NULL);
    ldap_search(NULL, NULL, 0, NULL, NULL, 0);
    ldap_unbind(NULL);
}

#ifdef HAVE_NT_SERVICE_MANAGER

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"

ldap_pvt_thread_cond_t	started_event,		stopped_event;
ldap_pvt_thread_t		start_status_tid,	stop_status_tid;


/* in main.c */
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv );

/* in ntservice.c */
int srv_install( char* service, char* filename );
int srv_remove ( char* service, char* filename );

int main( int argc, LPTSTR *argv )
{
	int		length;
	char	filename[MAX_PATH], *fname_start;
	extern int is_NT_Service;

	SERVICE_TABLE_ENTRY		DispatchTable[] = {
		{	SERVICE_NAME,	(LPSERVICE_MAIN_FUNCTION) ServiceMain	},
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
			if ( (argc > 2) && (argv[2] != NULL) )
				svcName = argv[2];
			if ( (length = GetModuleFileName(NULL, filename, sizeof( filename ))) == 0 ) 
			{
				fputs( "unable to retrieve file name for the service.\n", stderr  );
				return EXIT_FAILURE;
			}
			if ( !srv_install(svcName, filename) ) 
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

/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ntservice.c */
#include "portable.h"

#ifdef HAVE_NT_SERVICE_MANAGER

#include <ac/stdlib.h>
#include <ac/string.h>

#include <stdio.h>

#include <windows.h>
#include <winsvc.h>

#include <ldap.h>

#define ldap_debug slap_debug
extern int slap_debug;

#include "ldap_log.h"
#include "ldap_pvt_thread.h"


#include "ldap_defaults.h"

#include "slapdmsg.h"

#define SCM_NOTIFICATION_INTERVAL	5000
#define THIRTY_SECONDS				(30 * 1000)

int	  is_NT_Service = 1;	/* assume this is an NT service until determined that */
							/* startup was from the command line */

SERVICE_STATUS			SLAPDServiceStatus;
SERVICE_STATUS_HANDLE	hSLAPDServiceStatus;

ldap_pvt_thread_cond_t	started_event,		stopped_event;
ldap_pvt_thread_t		start_status_tid,	stop_status_tid;

void (*stopfunc)(int);

char *GetLastErrorString( void );

int srv_install(LPCTSTR lpszServiceName, LPCTSTR lpszDisplayName,
		LPCTSTR lpszBinaryPathName, BOOL auto_start)
{
	HKEY		hKey;
	DWORD		dwValue, dwDisposition;
	SC_HANDLE	schSCManager, schService;

	fprintf( stderr, "The install path is %s.\n", lpszBinaryPathName );
	if ((schSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE ) ) != NULL )
	{
	 	if ((schService = CreateService( 
							schSCManager, 
							lpszServiceName, 
							lpszDisplayName, 
							SERVICE_ALL_ACCESS, 
							SERVICE_WIN32_OWN_PROCESS, 
							auto_start ? SERVICE_AUTO_START : SERVICE_DEMAND_START, 
							SERVICE_ERROR_NORMAL, 
							lpszBinaryPathName, 
							NULL, NULL, NULL, NULL, NULL)) != NULL)
		{
			char regpath[132];
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);

			sprintf( regpath, "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",
				lpszServiceName );
			/* Create the registry key for event logging to the Windows NT event log. */
			if ( RegCreateKeyEx(HKEY_LOCAL_MACHINE, 
				regpath, 0, 
				"REG_SZ", REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, 
				&dwDisposition) != ERROR_SUCCESS)
			{
				fprintf( stderr, "RegCreateKeyEx() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
				RegCloseKey(hKey);
				return(0);
			}
			if ( RegSetValueEx(hKey, "EventMessageFile", 0, REG_EXPAND_SZ, lpszBinaryPathName, strlen(lpszBinaryPathName) + 1) != ERROR_SUCCESS)
			{
				fprintf( stderr, "RegSetValueEx(EventMessageFile) failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
				RegCloseKey(hKey);
				return(0);
			}

			dwValue = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
			if ( RegSetValueEx(hKey, "TypesSupported", 0, REG_DWORD, (LPBYTE) &dwValue, sizeof(DWORD)) != ERROR_SUCCESS) 
			{
				fprintf( stderr, "RegCreateKeyEx(TypesSupported) failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
				RegCloseKey(hKey);
				return(0);
			}
			RegCloseKey(hKey);
			return(1);
		}
		else
		{
			fprintf( stderr, "CreateService() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
			CloseServiceHandle(schSCManager);
			return(0);
		}
	}
	else
		fprintf( stderr, "OpenSCManager() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
	return(0);
}


int srv_remove(LPCTSTR lpszServiceName, LPCTSTR lpszBinaryPathName)
{
	SC_HANDLE schSCManager, schService;

	fprintf( stderr, "The installed path is %s.\n", lpszBinaryPathName );
	if ((schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT|SC_MANAGER_CREATE_SERVICE)) != NULL ) 
	{
	 	if ((schService = OpenService(schSCManager, lpszServiceName, DELETE)) != NULL) 
		{
			if ( DeleteService(schService) == TRUE) 
			{
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return(1);
			} else {
				fprintf( stderr, "DeleteService() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
				fprintf( stderr, "The %s service has not been removed.\n", lpszBinaryPathName);
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return(0);
			}
		} else {
			fprintf( stderr, "OpenService() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
			CloseServiceHandle(schSCManager);
			return(0);
		}
	}
	else
		fprintf( stderr, "OpenSCManager() failed. GetLastError=%lu (%s)\n", GetLastError(), GetLastErrorString() );
	return(0);
}



static void *start_status_routine( void *ptr )
{
	DWORD	wait_result;
	int		done = 0;

	while ( !done )
	{
		wait_result = WaitForSingleObject( started_event, SCM_NOTIFICATION_INTERVAL );
		switch ( wait_result )
		{
			case WAIT_ABANDONED:
			case WAIT_OBJECT_0:
				/* the object that we were waiting for has been destroyed (ABANDONED) or
				 * signalled (TIMEOUT_0). We can assume that the startup process is
				 * complete and tell the Service Control Manager that we are now runnng */
				SLAPDServiceStatus.dwCurrentState	= SERVICE_RUNNING;
				SLAPDServiceStatus.dwWin32ExitCode	= NO_ERROR;
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint		= 1000;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
				done = 1;
				break;
			case WAIT_TIMEOUT:
				/* We've waited for the required time, so send an update to the Service Control 
				 * Manager saying to wait again. */
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint = SCM_NOTIFICATION_INTERVAL * 2;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
				break;
			case WAIT_FAILED:
				/* theres been some problem with WaitForSingleObject so tell the Service
				 * Control Manager to wait 30 seconds before deploying its assasin and 
				 * then leave the thread. */
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint = THIRTY_SECONDS;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
				done = 1;
				break;
		}
	}
	ldap_pvt_thread_exit(NULL);
	return NULL;
}



static void *stop_status_routine( void *ptr )
{
	DWORD	wait_result;
	int		done = 0;

	while ( !done )
	{
		wait_result = WaitForSingleObject( stopped_event, SCM_NOTIFICATION_INTERVAL );
		switch ( wait_result )
		{
			case WAIT_ABANDONED:
			case WAIT_OBJECT_0:
				/* the object that we were waiting for has been destroyed (ABANDONED) or
				 * signalled (TIMEOUT_0). The shutting down process is therefore complete 
				 * and the final SERVICE_STOPPED message will be sent to the service control
				 * manager prior to the process terminating. */
				done = 1;
				break;
			case WAIT_TIMEOUT:
				/* We've waited for the required time, so send an update to the Service Control 
				 * Manager saying to wait again. */
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint = SCM_NOTIFICATION_INTERVAL * 2;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
				break;
			case WAIT_FAILED:
				/* theres been some problem with WaitForSingleObject so tell the Service
				 * Control Manager to wait 30 seconds before deploying its assasin and 
				 * then leave the thread. */
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint = THIRTY_SECONDS;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
				done = 1;
				break;
		}
	}
	ldap_pvt_thread_exit(NULL);
	return NULL;
}



void WINAPI SLAPDServiceCtrlHandler( IN DWORD Opcode)
{
	switch (Opcode)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:

		Debug( LDAP_DEBUG_TRACE, "Service Shutdown ordered\n", 0, 0, 0 );
		SLAPDServiceStatus.dwCurrentState	= SERVICE_STOP_PENDING;
		SLAPDServiceStatus.dwCheckPoint++;
		SLAPDServiceStatus.dwWaitHint		= SCM_NOTIFICATION_INTERVAL * 2;
		SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);

		ldap_pvt_thread_cond_init( &stopped_event );
		if ( stopped_event == NULL )
		{
			/* the event was not created. We will ask the service control manager for 30
			 * seconds to shutdown */
			SLAPDServiceStatus.dwCheckPoint++;
			SLAPDServiceStatus.dwWaitHint		= THIRTY_SECONDS;
			SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
		}
		else
		{
			/* start a thread to report the progress to the service control manager 
			 * until the stopped_event is fired. */
			if ( ldap_pvt_thread_create( &stop_status_tid, 0, stop_status_routine, NULL ) == 0 )
			{
				
			}
			else {
				/* failed to create the thread that tells the Service Control Manager that the
				 * service stopping is proceeding. 
				 * tell the Service Control Manager to wait another 30 seconds before deploying its
				 * assasin.  */
				SLAPDServiceStatus.dwCheckPoint++;
				SLAPDServiceStatus.dwWaitHint = THIRTY_SECONDS;
				SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
			}
		}
		stopfunc( -1 );
		break;

	case SERVICE_CONTROL_INTERROGATE:
		SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
		break;
	}
	return;
}

void *getRegParam( char *svc, char *value )
{
	HKEY hkey;
	char path[255];
	DWORD vType;
	static char vValue[1024];
	DWORD valLen = sizeof( vValue );

	if ( svc != NULL )
		sprintf ( path, "SOFTWARE\\%s", svc );
	else
		strcpy (path, "SOFTWARE\\OpenLDAP\\Parameters" );
	
	if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hkey ) != ERROR_SUCCESS )
	{
		/*Debug( LDAP_DEBUG_ANY, "RegOpenKeyEx() %s\n", GetLastErrorString(), 0, 0); */
		return NULL;
	}

	if ( RegQueryValueEx( hkey, value, NULL, &vType, vValue, &valLen ) != ERROR_SUCCESS )
	{
		/*Debug( LDAP_DEBUG_ANY, "RegQueryValueEx() %s\n", GetLastErrorString(), 0, 0 );*/
		RegCloseKey( hkey );
		return NULL;
	}
	RegCloseKey( hkey );
	
	switch ( vType )
	{
	case REG_BINARY:
	case REG_DWORD:
		return (void*)&vValue;
	case REG_SZ:
		return (void*)&vValue;
	}
	return (void*)NULL;
}

void LogSlapdStartedEvent( char *svc, int slap_debug, char *configfile, char *urls )
{
	char *Inserts[5];
	WORD i = 0, j;
	HANDLE hEventLog;
	
	hEventLog = RegisterEventSource( NULL, svc );

	Inserts[i] = (char *)malloc( 20 );
	itoa( slap_debug, Inserts[i++], 10 );
	Inserts[i++] = ldap_pvt_strdup( configfile );
	Inserts[i++] = ldap_pvt_strdup( urls ? urls : "ldap:///" );
	Inserts[i++] = ldap_pvt_strdup( is_NT_Service ? "svc" : "cmd" );

	ReportEvent( hEventLog, EVENTLOG_INFORMATION_TYPE, 0,
		MSG_SLAPD_STARTED, NULL, i, 0, (LPCSTR *) Inserts, NULL );

	for ( j = 0; j < i; j++ )
		ldap_memfree( Inserts[j] );
	DeregisterEventSource( hEventLog );
}



void LogSlapdStoppedEvent( char *svc )
{
	HANDLE hEventLog;
	
	hEventLog = RegisterEventSource( NULL, svc );
	ReportEvent( hEventLog, EVENTLOG_INFORMATION_TYPE, 0,
		MSG_SLAPD_STOPPED, NULL, 0, 0, NULL, NULL );
	DeregisterEventSource( hEventLog );
}


void CommenceStartupProcessing( LPCTSTR lpszServiceName,
							   void (*stopper)(int) )
{
	hSLAPDServiceStatus = RegisterServiceCtrlHandler( lpszServiceName, (LPHANDLER_FUNCTION)SLAPDServiceCtrlHandler);

	stopfunc = stopper;

	/* initialize the Service Status structure */
	SLAPDServiceStatus.dwServiceType				= SERVICE_WIN32_OWN_PROCESS;
	SLAPDServiceStatus.dwCurrentState				= SERVICE_START_PENDING;
	SLAPDServiceStatus.dwControlsAccepted			= SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	SLAPDServiceStatus.dwWin32ExitCode				= NO_ERROR;
	SLAPDServiceStatus.dwServiceSpecificExitCode	= 0;
	SLAPDServiceStatus.dwCheckPoint					= 1;
	SLAPDServiceStatus.dwWaitHint					= SCM_NOTIFICATION_INTERVAL * 2;

	SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);

	/* start up a thread to keep sending SERVICE_START_PENDING to the Service Control Manager
	 * until the slapd listener is completed and listening. Only then should we send 
	 * SERVICE_RUNNING to the Service Control Manager. */
	ldap_pvt_thread_cond_init( &started_event );
	if ( started_event == NULL)
	{
		/* failed to create the event to determine when the startup process is complete so
		 * tell the Service Control Manager to wait another 30 seconds before deploying its
		 * assasin  */
		SLAPDServiceStatus.dwCheckPoint++;
		SLAPDServiceStatus.dwWaitHint = THIRTY_SECONDS;
		SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
	}
	else
	{
		/* start a thread to report the progress to the service control manager 
		 * until the started_event is fired.  */
		if ( ldap_pvt_thread_create( &start_status_tid, 0, start_status_routine, NULL ) == 0 )
		{
			
		}
		else {
			/* failed to create the thread that tells the Service Control Manager that the
			 * service startup is proceeding. 
			 * tell the Service Control Manager to wait another 30 seconds before deploying its
			 * assasin.  */
			SLAPDServiceStatus.dwCheckPoint++;
			SLAPDServiceStatus.dwWaitHint = THIRTY_SECONDS;
			SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
		}
	}
}

void ReportSlapdShutdownComplete(  )
{
	if ( is_NT_Service )
	{
		/* stop sending SERVICE_STOP_PENDING messages to the Service Control Manager */
		ldap_pvt_thread_cond_signal( &stopped_event );
		ldap_pvt_thread_cond_destroy( &stopped_event );

		/* wait for the thread sending the SERVICE_STOP_PENDING messages to the Service Control Manager to die.
		 * if the wait fails then put ourselves to sleep for half the Service Control Manager update interval */
		if (ldap_pvt_thread_join( stop_status_tid, (void *) NULL ) == -1)
			ldap_pvt_thread_sleep( SCM_NOTIFICATION_INTERVAL / 2 );

		SLAPDServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SLAPDServiceStatus.dwCheckPoint++;
		SLAPDServiceStatus.dwWaitHint = SCM_NOTIFICATION_INTERVAL;
		SetServiceStatus(hSLAPDServiceStatus, &SLAPDServiceStatus);
	}
}

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
#endif

/*
 * console.c -- simple windows console emulator for Winsock testing
 * 27 June 1993 by Mark C Smith
 */
#include <stdio.h>
#include <winsock.h>
#include <string.h>
#include "console.h"

static char *argv[] = { "console", "rearwindow", 0 };	/* */
char szAppName[20];
char szLineBuf[512];
HWND hInst;          
HWND hWndMain, hWndOutputEdit;
HANDLE hAccel;

int reg_classes( void );
void unreg_classes( void );



int PASCAL
WinMain( HANDLE hInstance, HANDLE hPrevInst, LPSTR lpszCmdLine, int nCmdShow)
{
    MSG msg;
    int rc;

    strcpy( szAppName, "console");

    hInst = hInstance;
    if ( !hPrevInst ) {
	if (( rc = reg_classes()) != 0 ) {
	   MessageBox(0, "Couldn't register window classes", NULL, MB_ICONEXCLAMATION);
	   return( rc );
	}
    }

    hWndMain = CreateWindow(
                szAppName,               /* Window class name           */
		"Console",		/* Window's title              */
                WS_CAPTION      |        /* Title and Min/Max           */
                WS_SYSMENU      |        /* Add system menu box         */
                WS_MINIMIZEBOX  |        /* Add minimize box            */
                WS_MAXIMIZEBOX  |        /* Add maximize box            */
                WS_THICKFRAME   |        /* thick sizeable frame        */
                WS_CLIPCHILDREN |         /* don't draw in child windows areas */
                WS_OVERLAPPED,
                CW_USEDEFAULT, 0,        /* Use default X, Y            */
                CW_USEDEFAULT, 0,        /* Use default X, Y            */
		0,			  /* Parent window's handle      */
		0,			  /* Default to Class Menu	 */
                hInst,                   /* Instance of window          */
		NULL ); 		 /* Create struct for WM_CREATE */

    if( !hWndMain ) {
	MessageBox( 0, "Couldn't create main window", NULL, MB_ICONEXCLAMATION);
	return( -1 );
    }

    ShowWindow( hWndMain, nCmdShow );

    hAccel = LoadAccelerators( hInst, szAppName );

    if (( hWndOutputEdit = new_editwindow( hWndMain, "console output" )) == NULL ) {
	MessageBox( 0, "Couldn't create output window", NULL, MB_ICONEXCLAMATION);
	return( -1 );
    }

    while( GetMessage( &msg, 0, 0, 0 )) {
	if( TranslateAccelerator( hWndMain, hAccel, &msg )) {
	    continue;
	}

	TranslateMessage(&msg);
	DispatchMessage(&msg);
    }

    unreg_classes();
    return( msg.wParam );
}

LONG FAR PASCAL
WndProc( HWND hWnd, WORD msg, WORD wParam, LONG lParam )
{
    HDC	    hDC;
    PAINTSTRUCT ps;

    switch( msg ) {
    case WM_COMMAND:
	switch( wParam ) {
	case IDM_F_OPENLDAP:
	    ldapmain( 2, argv );
	    break;

	case IDM_F_EXIT:
	    PostQuitMessage( 0 );
	    break;

	default:
	   return( DefWindowProc( hWnd, msg, wParam, lParam ));
     }

    case WM_CREATE:
	 break;

    case WM_MOVE:
         break;

    case WM_SIZE:
	 break;

    case WM_PAINT:
	memset( &ps, 0x00, sizeof( PAINTSTRUCT ));
	hDC = BeginPaint( hWnd, &ps );
	SetBkMode(hDC, TRANSPARENT);

	EndPaint(hWnd, &ps);
	break;

    case WM_CLOSE:
	DestroyWindow(hWnd);
	if ( hWnd == hWndMain ) {
	    PostQuitMessage( 0 );
	}
        break;

    default:
	 return( DefWindowProc( hWnd, msg, wParam, lParam ));
   }

   return( 0L );
}

int
reg_classes( void )
{
    WNDCLASS   wndclass;
    memset( &wndclass, 0x00, sizeof( WNDCLASS ));


    wndclass.style = CS_HREDRAW | CS_VREDRAW | CS_BYTEALIGNWINDOW;
    wndclass.lpfnWndProc = WndProc;
    wndclass.cbClsExtra = 0;
    wndclass.cbWndExtra = 0;
    wndclass.hInstance = hInst;
    wndclass.hIcon = LoadIcon(hInst, "CONSOLE");
    wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH)( COLOR_WINDOW+1 );
    wndclass.lpszMenuName = szAppName;	/* Menu Name is App Name */
    wndclass.lpszClassName = szAppName; /* Class Name is App Name */
    if( !RegisterClass( &wndclass )) {
	return( -1 );
    }

    return( 0 );
}

void
unreg_classes( void )
{
    UnregisterClass( szAppName, hInst );
}


char *
getline( char *line, int len, FILE *s, char *prompt )
{
     FARPROC lpfnDlgProc;
     int	nRc;

     printf( prompt );

     lpfnDlgProc = MakeProcInstance((FARPROC)GetLineDlgProc, hInst);
     nRc = DialogBox(hInst, MAKEINTRESOURCE(200), hWndMain, lpfnDlgProc);
     FreeProcInstance(lpfnDlgProc);
     if ( !nRc ) {
	return( NULL );
     }
     strncpy( line, szLineBuf, len );
     printf( "%s\n", line );
     return( line );
}



void
perror( char *msg )
{
    printf( "%s: error %d\n", msg, WSAGetLastError());
}

void
appexit( int rc )
{
    printf( "exit( %d )\n", rc );
}

int
fprintf( FILE *f, char *fmt, void *a1, void *a2, void *a3, void *a4,
    void *a5 )
{
    printf( fmt, a1, a2, a3, a4, a5 );
}

int
printf( char *fmt, void *a1, void *a2, void *a3, void *a4, void *a5 )
{
    char *p, *send, buf[ 1024 ], *crlf = "\r\n";

    sprintf( buf, fmt, a1, a2, a3, a4, a5 );

    send = buf;
    for ( p = buf; *p != '\0'; ++p ) {
	if ( *p == '\n' ) {
	    *p = '\0';
	    SendMessage( hWndOutputEdit, EM_REPLACESEL, 0, (long)send );
	    SendMessage( hWndOutputEdit, EM_REPLACESEL, 0, (long)crlf );
	    send = p + 1;
	}
    }

    if ( p > send ) {
	SendMessage( hWndOutputEdit, EM_REPLACESEL, 0, (long)send );
    }
}

BOOL FAR PASCAL
GetLineDlgProc(HWND hWndDlg, WORD Message, WORD wParam, LONG lParam)
{
   switch(Message) {
   case WM_INITDIALOG:
	 /* cwCenter(hWndDlg, 0); */
	 break;

    case WM_CLOSE:
         /* Closing the Dialog behaves the same as Cancel               */
         PostMessage(hWndDlg, WM_COMMAND, IDCANCEL, 0L);
	 break;

    case WM_COMMAND:
	 switch(wParam) {
	     case IDOK:
	     SendDlgItemMessage( hWndDlg, DLG_GETLINE_TEXT, WM_GETTEXT, sizeof( szLineBuf),
		(long)szLineBuf );
	     EndDialog(hWndDlg, TRUE);
	     break;
	 case IDCANCEL:
	     EndDialog(hWndDlg, FALSE);
	     break;
	}
	break;

    default:
        return FALSE;
    }
    return TRUE;
}

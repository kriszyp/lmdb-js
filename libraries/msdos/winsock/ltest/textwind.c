/*
 * textwind.c
 */
#include <windows.h>
#include <stdio.h>
#include "console.h"
#include "textwind.h"

static BOOL windclassreg = FALSE;
extern HWND hInst;

/*
 * local prototypes
 */
BOOL register_editclass( void );


HWND
new_editwindow( HWND hParent, char *lpszTitle )
{
	HWND	hWnd, hEditWnd;
	RECT	r;

	/*
	 * register text edit window class if we have not already done so
	 */
	if ( !windclassreg && !register_editclass()) {
		return( NULL );
	}

	/*
	 * create an instance of text edit window
	 */
	hWnd = CreateWindow( WINDCLASS_TEDIT, lpszTitle != NULL ? lpszTitle : "Untitled",
			WS_OVERLAPPEDWINDOW,
			CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
			hParent, NULL, hInst, NULL );

	if ( !hWnd ) {
		return( NULL );
	}

	/*
	 * create a child Edit controls that fills the text edit window
	 */
	GetClientRect( hWnd, (LPRECT)&r );
	hEditWnd = CreateWindow( "Edit", NULL,
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_MULTILINE,
			0, 0, r.right - r.left, r.bottom - r.top, hWnd, IDC_EDIT, hInst, NULL );

	if ( !hEditWnd ) {
		DestroyWindow( hWnd );
		return( NULL );
	}

	/*
	 * add edit control to property list of window
	 */
	if( !SetProp( hWnd, "hEditWnd", hEditWnd )) {
		DestroyWindow( hWnd );
		return( NULL );
	}

	if ( lpszTitle != NULL ) {
	    SetWindowText( hWnd, lpszTitle );
	}

	/*
	 * show and draw the new window
	 */
	ShowWindow( hWnd, SW_SHOWNORMAL );
	UpdateWindow( hWnd );
	return( hEditWnd );
}


BOOL
register_editclass()
{
	WNDCLASS	wc;

	memset( &wc, 0x00, sizeof(WNDCLASS) );

	wc.style = CS_HREDRAW | CS_VREDRAW | CS_BYTEALIGNWINDOW;
	wc.lpfnWndProc = TEditWndProc;
	wc.hInstance = hInst;
	wc.hbrBackground = (HBRUSH) (COLOR_WINDOW + 1 );
	wc.lpszClassName = WINDCLASS_TEDIT;
	return( windclassreg = RegisterClass( &wc ));
}


void
memory_error( void )
{
	MessageBox( GetFocus(), "Out of memory", "Sample", MB_ICONHAND | MB_OK );
}


long FAR PASCAL TEditWndProc( HWND hWnd, unsigned message, WORD wParam, LONG lParam )
{
	HWND	hEditWnd;

	hEditWnd = GetProp( hWnd, "hEditWnd" );

	switch( message ) {
	case WM_COMMAND:
		switch( wParam ) {
		case IDC_EDIT:
			if ( HIWORD( lParam ) == EN_ERRSPACE ) {
				memory_error();
			}
			break;
		}
		break;

	case WM_SETFOCUS:
		SetFocus( hEditWnd );
		break;

	case WM_SIZE:
		MoveWindow( hEditWnd, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE );
		break;

	default:
		return( DefWindowProc( hWnd, message, wParam, lParam ));
	}

	return( NULL );
}

/*
 * console.h -- defines for a simple windows console emulator
 * 27 June 1993 by Mark C Smith
 */

#define IDM_FILE	  1000
#define IDM_F_OPENLDAP	    1050
#define IDM_F_EXIT	    1100
#define DLG_GETLINE_TEXT	    102

#define exit( e )	appexit( e ); return( e )

void perror( char *msg );
int printf( char *fmt, ... );
int fprintf( FILE *f, char *fmt, ... );
void appexit( int rc );
char *getline( char *line, int len, FILE *s, char *prompt );
LONG FAR PASCAL WndProc( HWND, WORD, WORD, LONG );
BOOL FAR PASCAL GetLineDlgProc(HWND hWndDlg, WORD Message, WORD wParam, LONG lParam);

/*
 * textwind.h
 */

#define	WINDCLASS_TEDIT	"TextClass"
#define IDC_EDIT		100

/*
 * prototypes
 */
HWND new_editwindow( HWND hParent, char *lpszTtitle );
void memory_error( void );
long FAR PASCAL TEditWndProc( HWND hWnd, unsigned message, WORD wParam, LONG lParam );

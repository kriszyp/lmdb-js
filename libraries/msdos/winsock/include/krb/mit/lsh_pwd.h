/* LSH_PWD.H this is the include file for the LSH_PWD.C  */

/* Included from krb.h - CRS 940805 */

#ifndef __LSH_PWD__
#define __LSH_PWD__

// Definition of the info structure that is passed to tell the dialog box what state it
//  should be in.

#include <stdio.h>

typedef struct {
  int dlgtype;
#define DLGTYPE_PASSWD   0
#define DLGTYPE_CHPASSWD 1
  int dlgstatemax;             // I am not sure what this is yet.  STUFF TO DO!
  LPSTR title;                 // The title on the Dialog box - for Renewing or Initializing.
  LPSTR principal;
} LSH_DLGINFO, FAR *LPLSH_DLGINFO;


// Some defines swiped from leash.h
//  These are necessary but they must be kept sync'ed with leash.h
#define HELPFILE "kerberos.hlp"
#define PASSWORDCHAR '#'

#define DLGHT(ht) (HIWORD(GetDialogBaseUnits())*(ht)/8)
#define DLGWD(wd) (LOWORD(GetDialogBaseUnits())*(wd)/4)

// external variables
#ifdef PDLL
long lsh_errno;
char *err_context;       /* error context */
char FAR *kadm_info; /* to get info from the kadm* files */
long dlgu;                              /* dialog units  */
#ifdef WINSOCK
HINSTANCE hinstWinSock = NULL;
#endif // WINSOCK
#endif // PDLL

// local macros  stolen from leash.h
#ifndef MAKEWORD
#define MAKEWORD(low, high) ((WORD)(((BYTE)(low)) | (((UINT)((BYTE)(high))) << 8)))
#endif /*MAKEWORD*/


// Function Prototypes.
int FAR PASCAL _export Lsh_Enter_Password_Dialog(HWND hParent, LPLSH_DLGINFO lpdlginfo);
int FAR PASCAL _export Lsh_Change_Password_Dialog(HWND hParent, LPLSH_DLGINFO lpdlginfo);
int lsh_com_err_proc (LPSTR whoami, long code, LPSTR fmt, va_list args);
int _export DoNiftyErrorReport(long errnum, LPSTR what);
LONG FAR PASCAL _export MITPwdWinProcDLL(HWND hWnd, WORD message, WORD wParam, LONG lParam);
BOOL FAR PASCAL _export PasswordProcDLL(HWND hDialog, WORD message, WORD wParam, LONG lParam);
LONG FAR PASCAL _export lsh_get_lsh_errno( LONG FAR *err_val);
#endif __LSH_PWD__

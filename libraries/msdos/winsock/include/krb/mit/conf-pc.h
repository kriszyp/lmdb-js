/*
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Machine-type definitions: IBM PC 8086
 */

#include <mit_copy.h>

#ifndef IBMPC
        #define IBMPC
#endif

#if defined(__WINDOWS__) && !defined(WINDOWS)
#define WINDOWS
#endif

#if defined(__OS2__) && !defined(OS2)
#define OS2
#endif

#ifndef OS2
#define BITS16
#define CROSSMSDOS
/* OS/2 is 32 bit!!!! */
#else
#define BITS32
#endif
#define LSBFIRST

#define index(s,c) strchr(s,c)          /* PC version of index */
#define rindex(s,c) strrchr(s,c)

typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef short uid_t;

#if !defined(WINDOWS) && !defined(DWORD)
typedef long DWORD;
#endif

#ifdef OS2
typedef char *LPSTR;
typedef char *LPBYTE;
typedef char *CHARPTR;
typedef char *LPINT;
typedef unsigned int WORD;

#define far
#define near
#define FAR
#define PASCAL
#include <utils.h>
#define lstrcpy strcpy
#define lstrlen strlen
#define lstrcmp strcmp
#define lstrcpyn strncpy
#endif

#if defined(OS2) || defined(WINDOWS)
#define creat _creat
#define read _read
#define write _write
#define open _open
#define close _close
#define stat(x,y) _stat(x,y)
#define putch _putch
#define getch _getch
#endif

#ifdef WINDOWS
#include <windows.h>
#endif

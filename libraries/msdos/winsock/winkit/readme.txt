
LDAP (Lightweight Directory Access Protocol) API for Windows/Winsock

The lber and ldap client libraries have been ported to Microsoft Windows
in the form of Windows Dynamic Link libraries called LIBLDAP.DLL (16Bit)
and Ldap32.dll (32Bit).  The LTest program is also provided in both
formats.

A Windows Sockets API (version 1.1 conformant) TCP/IP WINSOCK.DLL or
WSOCK32.DLL is required for the DLL to run.

Our intent is that this "kit" include everything you'll need to make use
of the ldap client API from your 16Bit or 32Bit application.  If you
find something missing or have a suggestion for improvement, send email
to the "bug reporting" address at the bottom of this file.

To use this "kit"

    1) Get to a DOS prompt
	
    2) Create the directory you want this to live in (e.g.  \ldap)
       and cd into it.  We will refer to that directory simply as
       "\ldap" from now on, but it could be anywhere and have any name
       you desire.

    3) Use "pkunzip -d" to extract the files.  The "-d" is NECESSARY to
       preserve the subdirectories and avoid file name collisions.

    4) We have included only the files you need to use and test
       libldap.dll and ldap32.dll.  If you want the entire distribution, 
       with source, you can get it from:

           ftp://terminator.rs.itd.umich.edu/ldap/ldap-3.3.tar.Z

The following files are included in this distribution:

    16Bit binaries and libs
	BINARIES/DEBUG/LIBLDAP.DLL
	BINARIES/DEBUG/LIBLDAP.LIB
	BINARIES/RELEASE/LIBLDAP.DLL
	BINARIES/RELEASE/LIBLDAP.LIB

	BINARIES/DEBUG/LTEST.EXE

    32Bit binaries and libs
	BINARIES/DEBUG/LDAP32.DLL
	BINARIES/DEBUG/LDAP32.LIB
	BINARIES/RELEASE/LDAP32.DLL
	BINARIES/RELEASE/LDAP32.LIB

	BINARIES/DEBUG/LTEST32.EXE

    Include files
	INCKIT/MSDOS.H
	INCKIT/LBER.H
	INCKIT/LDAP.H
	INCKIT/PROTO-LD.H
	INCKIT/PROTO-LB.H
	INCKIT/SRCHPREF.H
	INCKIT/DISPTMPL.H

    Sample Configuration files
	SRCHPREF.CFG
	DISPTMPL.CFG
	LDFRIEND.CFG
	LDFILTER.CFG

    Man pages in the form of Windows HLP files
	LIBLDAP.HLP	- old format hlp file
	LDAP32.HLP	- new format hlp file, both have same content

16Bit versions

    Libldap.dll was compiled with KERBEROS, AUTHMAN, WSHELPER, WIN32,
    _WINDOWS,& LDAP_REFERRALS defined.  Even if you do not need kerberos
    authentication, (see below for more information on kerberos) this
    dll should work correctly for you.

    LDAP_REFERRALS makes libldap.dll capable of handling referrals
    returned by a slapd server.

32Bit versions

    The 32Bit version is NOT SAFE for MULTIPLE THREADS at this time.
    Not more than one thread per application may make use of the
    ldap routines.

    Ldap32.dll was compiled with LDAP_REFERRALS defined and is capable
    of handling referrals returned by a slapd server.


WRITING APPLICATIONS THAT USE LIBLDAP.DLL or LDAP32.DLL

    All of the normal LDAP and LBER calls documented in the help file
    should work, except for ldap_perror (this is not supported under
    Windows since you will want to use an application-defined dialog;
    you can use ldap_err2string to obtain an error string to display in
    a message box or dialog).  

    The man pages are included in this kit in the form of windows HLP files.
    The official source man pages are available via the web at:

	    http://www.umich.edu/ldap/doc/man/

    Any memory that you obtain as the result of a call to an LIBLDAP.DLL
    routine should NOT be freed by calling the free() routine in your C
    library.  Instead, use the the new utility routine ldap_memfree or
    the appropriate ldap ...free routine.  This is so the malloc/calloc
    and free routines all come from the same library (the one in
    libldap) rather than using libldap's malloc/calloc and the calling
    program's free.  Microsoft's VC++ 4.0 compiler (in debug mode)
    FORCED me to be compulsive about this for the application I used to
    test.

    To be friendly under Windows, you should use the asynchronous LDAP
    calls whenever possible.

    One limitation of the current LIBLDAP.DLL is that each X.500 LDAP
    result message has to be smaller than 64K bytes.  Ldap32.dll does
    NOT have this limitation.

    To compile the ldap dlls we define the following preprocessor variables.

        WINSOCK, DOS, NEEDPROTOS, NO_USERINTERFACE, KERBEROS
    
    Presumably you don't need KERBEROS.  You may need some/all the others
    to take the right path through the include files.  Also note that a
    few more preprocessor variables are defined in msdos.h.  This means that
    msdos.h must be included before ldap.h or lber.h.
    

LTest and LTtest32 

    The LTest.exe and LTest32.exe programs are test interfaces to libldap
    and ldap32 respectively.  By default they connect to the host 
    "truelies".  This host name is contained in a string resource in the
    exe file.  You may easily "customize" this to be the name of whatever
    server you're using with AppStudio or any Windows resource editor.

Kerberos Information

    Libldap.dll was compiled with KERBEROS, AUTHMAN, WSHELPER, &
    LDAP_REFERRALS defined.  If you do not need kerberos authentication,
    this dll should still work correctly for you.  Libldap.dll
    dynamically loads and uses the dlls needed for kerberos
    authentication (Authlib.dll, Krbv4win.dll, & WSHelper.dll).  If
    Libldap.dll is unable to load the needed dlls, execution continues
    without error, but without kerberos authentication capability.

    AUTHMAN allows libldap.dll to make use of Authlib.dll (which
    requires KrbV4Win.dll & WSHelper.dll) if they are ALL in the "PATH".
    If these are not available, kerberos authentication can not succede,
    but libldap.dll will execute without error.

    WSHELPER means that if WSHelper.dll is in the "PATH", it will be
    dynamically loaded and used to do the gethostbyaddr() call required
    for kerberos authentication to work.  (This is used because so many
    vendor implementations of gethostbyaddr return WRONG results.  We
    are working with all vendors we can get to listen to get these
    implementations fixed.)  If WSHelper.dll is not in the "PATH"
    libldap.dll does not fail to execute correctly.

    Ldap32.dll does NOT have the ability to do kerberos authentication
    because none of Authlib.dll, krbv4win.dll or wshelper.dll have been
    ported to 32Bits at this time.

    For further information on using kerberos with the ldap DLLs send
    email to ldap-support@umich.edu.

BUG REPORTING

    Bug reports should be sent to bug-ldap@umich.edu.


Miscellaneous

    Build testing was done on Windows NT workstation 3.51 (build 1057
    service pack 2) on an NTFS file system (which supports long
    filenames) using Microsoft Visual C++ 1.52c (16 bit) and Visual C++
    4.0 (32 bit).

README Last updated 11 January 1996 by Steve Rothwell

# Microsoft Developer Studio Project File - Name="libldap_r" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libldap_r - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libldap_r.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libldap_r.mak" CFG="libldap_r - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libldap_r - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libldap_r - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libldap_r - Win32 Single Debug" (based on\
 "Win32 (x86) Static Library")
!MESSAGE "libldap_r - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "libldap_r - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\libldap_r"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /D _WIN32_WINNT=0x0400 /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Release\oldap_r.lib"

!ELSEIF  "$(CFG)" == "libldap_r - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\libldap_r"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "_DEBUG" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /D _WIN32_WINNT=0x0400 /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Debug\oldap_r.lib"

!ELSEIF  "$(CFG)" == "libldap_r - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libldap_"
# PROP BASE Intermediate_Dir "libldap_"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\libldap_r"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "_DEBUG" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\..\include" /D "_DEBUG" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Debug\oldap_r.lib"
# ADD LIB32 /nologo /out:"..\..\SDebug\oldap_r.lib"

!ELSEIF  "$(CFG)" == "libldap_r - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libldap0"
# PROP BASE Intermediate_Dir "libldap0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\libldap_r"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "LDAP_R_COMPILE" /D "WIN32" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Release\oldap_r.lib"
# ADD LIB32 /nologo /out:"..\..\SRelease\oldap_r.lib"

!ENDIF 

# Begin Target

# Name "libldap_r - Win32 Release"
# Name "libldap_r - Win32 Debug"
# Name "libldap_r - Win32 Single Debug"
# Name "libldap_r - Win32 Single Release"
# Begin Source File

SOURCE=..\libldap\abandon.c
# End Source File
# Begin Source File

SOURCE=..\libldap\add.c
# End Source File
# Begin Source File

SOURCE=..\libldap\addentry.c
# End Source File
# Begin Source File

SOURCE=..\libldap\bind.c
# End Source File
# Begin Source File

SOURCE=..\libldap\cache.c
# End Source File
# Begin Source File

SOURCE=..\libldap\charray.c
# End Source File
# Begin Source File

SOURCE=..\libldap\compare.c
# End Source File
# Begin Source File

SOURCE=..\libldap\controls.c
# End Source File
# Begin Source File

SOURCE=..\libldap\cyrus.c
# End Source File
# Begin Source File

SOURCE=..\libldap\delete.c
# End Source File
# Begin Source File

SOURCE=..\libldap\dnssrv.c
# End Source File
# Begin Source File

SOURCE=..\libldap\dsparse.c
# End Source File
# Begin Source File

SOURCE=..\libldap\error.c
# End Source File
# Begin Source File

SOURCE=..\libldap\extended.c
# End Source File
# Begin Source File

SOURCE=..\libldap\filter.c
# End Source File
# Begin Source File

SOURCE=..\libldap\free.c
# End Source File
# Begin Source File

SOURCE=..\libldap\getattr.c
# End Source File
# Begin Source File

SOURCE=..\libldap\getdn.c
# End Source File
# Begin Source File

SOURCE=..\libldap\getentry.c
# End Source File
# Begin Source File

SOURCE=..\libldap\getfilter.c
# End Source File
# Begin Source File

SOURCE=..\libldap\getvalues.c
# End Source File
# Begin Source File

SOURCE=..\libldap\init.c
# End Source File
# Begin Source File

SOURCE=..\libldap\kbind.c
# End Source File
# Begin Source File

SOURCE="..\libldap\ldap-int.h"
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_cdefs.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_config.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_defaults.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_features.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_int_thread.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_log.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_pvt.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_pvt_thread.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_pvt_uc.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_queue.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_schema.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_utf8.h
# End Source File
# Begin Source File

SOURCE=..\libldap\modify.c
# End Source File
# Begin Source File

SOURCE=..\libldap\modrdn.c
# End Source File
# Begin Source File

SOURCE=..\libldap\open.c
# End Source File
# Begin Source File

SOURCE=..\libldap\options.c
# End Source File
# Begin Source File

SOURCE="..\libldap\os-ip.c"
# End Source File
# Begin Source File

SOURCE=..\libldap\print.c
# End Source File
# Begin Source File

SOURCE=.\rdwr.c
# ADD CPP /I "..\libldap"
# End Source File
# Begin Source File

SOURCE=..\libldap\request.c
# End Source File
# Begin Source File

SOURCE=..\libldap\result.c
# End Source File
# Begin Source File

SOURCE=..\libldap\sasl.c
# End Source File
# Begin Source File

SOURCE=..\libldap\sbind.c
# End Source File
# Begin Source File

SOURCE=..\libldap\schema.c
# End Source File
# Begin Source File

SOURCE=..\libldap\search.c
# End Source File
# Begin Source File

SOURCE=..\libldap\sort.c
# End Source File
# Begin Source File

SOURCE=..\libldap\sortctrl.c
# End Source File
# Begin Source File

SOURCE=..\libldap\string.c
# End Source File
# Begin Source File

SOURCE=.\thr_nt.c
# End Source File
# Begin Source File

SOURCE=.\thr_stub.c
# End Source File
# Begin Source File

SOURCE=.\threads.c
# End Source File
# Begin Source File

SOURCE=..\libldap\tls.c
# End Source File
# Begin Source File

SOURCE=.\tpool.c
# ADD CPP /I "..\libldap"
# End Source File
# Begin Source File

SOURCE=..\libldap\unbind.c
# End Source File
# Begin Source File

SOURCE=..\libldap\url.c
# End Source File
# Begin Source File

SOURCE="..\libldap\utf-8-conv.c"
# End Source File
# Begin Source File

SOURCE="..\libldap\utf-8.c"
# End Source File
# Begin Source File

SOURCE="..\libldap\util-int.c"
# End Source File
# Begin Source File

SOURCE=..\libldap\vlvctrl.c
# End Source File
# End Target
# End Project

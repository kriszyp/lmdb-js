# Microsoft Developer Studio Project File - Name="libldap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libldap - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libldap.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libldap.mak" CFG="libldap - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libldap - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libldap - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libldap - Win32 Single Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libldap - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "libldap - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\libldap"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Release\oldap32.lib"

!ELSEIF  "$(CFG)" == "libldap - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\libldap"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Debug\oldap32.lib"

!ELSEIF  "$(CFG)" == "libldap - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libldap_"
# PROP BASE Intermediate_Dir "libldap_"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\libldap"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Debug\oldap32.lib"
# ADD LIB32 /nologo /out:"..\..\SDebug\oldap32.lib"

!ELSEIF  "$(CFG)" == "libldap - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libldap0"
# PROP BASE Intermediate_Dir "libldap0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\libldap"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Release\oldap32.lib"
# ADD LIB32 /nologo /out:"..\..\SRelease\oldap32.lib"

!ENDIF 

# Begin Target

# Name "libldap - Win32 Release"
# Name "libldap - Win32 Debug"
# Name "libldap - Win32 Single Debug"
# Name "libldap - Win32 Single Release"
# Begin Source File

SOURCE=.\abandon.c
# End Source File
# Begin Source File

SOURCE=.\add.c
# End Source File
# Begin Source File

SOURCE=.\addentry.c
# End Source File
# Begin Source File

SOURCE=.\bind.c
# End Source File
# Begin Source File

SOURCE=.\cache.c
# End Source File
# Begin Source File

SOURCE=.\cancel.c
# End Source File
# Begin Source File

SOURCE=.\charray.c
# End Source File
# Begin Source File

SOURCE=.\compare.c
# End Source File
# Begin Source File

SOURCE=.\controls.c
# End Source File
# Begin Source File

SOURCE=.\cyrus.c
# End Source File
# Begin Source File

SOURCE=.\delete.c
# End Source File
# Begin Source File

SOURCE=.\dnssrv.c
# End Source File
# Begin Source File

SOURCE=.\error.c
# End Source File
# Begin Source File

SOURCE=.\extended.c
# End Source File
# Begin Source File

SOURCE=.\filter.c
# End Source File
# Begin Source File

SOURCE=.\free.c
# End Source File
# Begin Source File

SOURCE=.\getattr.c
# End Source File
# Begin Source File

SOURCE=.\getdn.c
# End Source File
# Begin Source File

SOURCE=.\getentry.c
# End Source File
# Begin Source File

SOURCE=.\getvalues.c
# End Source File
# Begin Source File

SOURCE=.\init.c
# End Source File
# Begin Source File

SOURCE=.\kbind.c
# End Source File
# Begin Source File

SOURCE=".\ldap-int.h"
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

SOURCE=..\..\include\ldap_log.h
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_pvt.h
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

SOURCE=.\messages.c
# End Source File
# Begin Source File

SOURCE=.\modify.c
# End Source File
# Begin Source File

SOURCE=.\modrdn.c
# End Source File
# Begin Source File

SOURCE=.\open.c
# End Source File
# Begin Source File

SOURCE=.\options.c
# End Source File
# Begin Source File

SOURCE=".\os-ip.c"
# End Source File
# Begin Source File

SOURCE=.\passwd.c
# End Source File
# Begin Source File

SOURCE=..\..\include\portable.h
# End Source File
# Begin Source File

SOURCE=.\print.c
# End Source File
# Begin Source File

SOURCE=.\references.c
# End Source File
# Begin Source File

SOURCE=.\request.c
# End Source File
# Begin Source File

SOURCE=.\result.c
# End Source File
# Begin Source File

SOURCE=.\sasl.c
# End Source File
# Begin Source File

SOURCE=.\sbind.c
# End Source File
# Begin Source File

SOURCE=.\schema.c
# End Source File
# Begin Source File

SOURCE=.\search.c
# End Source File
# Begin Source File

SOURCE=.\sort.c
# End Source File
# Begin Source File

SOURCE=.\sortctrl.c
# End Source File
# Begin Source File

SOURCE=.\string.c
# End Source File
# Begin Source File

SOURCE=.\tls.c
# End Source File
# Begin Source File

SOURCE=.\unbind.c
# End Source File
# Begin Source File

SOURCE=.\url.c
# End Source File
# Begin Source File

SOURCE=".\utf-8-conv.c"
# End Source File
# Begin Source File

SOURCE=".\utf-8.c"
# End Source File
# Begin Source File

SOURCE=".\util-int.c"
# End Source File
# Begin Source File

SOURCE=.\vlvctrl.c
# End Source File
# Begin Source File

SOURCE=.\whoami.c
# End Source File
# End Target
# End Project

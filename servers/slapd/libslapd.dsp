# Microsoft Developer Studio Project File - Name="libslapd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libslapd - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libslapd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libslapd.mak" CFG="libslapd - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libslapd - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libslapd - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libslapd - Win32 Single Debug" (based on\
 "Win32 (x86) Static Library")
!MESSAGE "libslapd - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "libslapd - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libslapd"
# PROP BASE Intermediate_Dir "libslapd"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\libslapd"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libslapd - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libslap0"
# PROP BASE Intermediate_Dir "libslap0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\libslapd"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libslapd - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libslap1"
# PROP BASE Intermediate_Dir "libslap1"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\libslapd"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "libslapd - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libslap2"
# PROP BASE Intermediate_Dir "libslap2"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\libslapd"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "libslapd - Win32 Release"
# Name "libslapd - Win32 Debug"
# Name "libslapd - Win32 Single Debug"
# Name "libslapd - Win32 Single Release"
# Begin Source File

SOURCE=.\abandon.c
# End Source File
# Begin Source File

SOURCE=.\acl.c
# End Source File
# Begin Source File

SOURCE=.\aclparse.c
# End Source File
# Begin Source File

SOURCE=.\ad.c
# End Source File
# Begin Source File

SOURCE=.\add.c
# End Source File
# Begin Source File

SOURCE=.\at.c
# End Source File
# Begin Source File

SOURCE=.\attr.c
# End Source File
# Begin Source File

SOURCE=.\ava.c
# End Source File
# Begin Source File

SOURCE=.\backend.c
# End Source File
# Begin Source File

SOURCE=.\backglue.c
# End Source File
# Begin Source File

SOURCE=.\bind.c
# End Source File
# Begin Source File

SOURCE=.\ch_malloc.c
# End Source File
# Begin Source File

SOURCE=.\compare.c
# End Source File
# Begin Source File

SOURCE=.\config.c
# End Source File
# Begin Source File

SOURCE=.\connection.c
# End Source File
# Begin Source File

SOURCE=.\controls.c
# End Source File
# Begin Source File

SOURCE=.\cr.c
# End Source File
# Begin Source File

SOURCE=.\daemon.c
# End Source File
# Begin Source File

SOURCE=.\delete.c
# End Source File
# Begin Source File

SOURCE=.\dn.c
# End Source File
# Begin Source File

SOURCE=.\entry.c
# End Source File
# Begin Source File

SOURCE=.\extended.c
# End Source File
# Begin Source File

SOURCE=.\filter.c
# End Source File
# Begin Source File

SOURCE=.\filterentry.c
# End Source File
# Begin Source File

SOURCE=.\index.c
# End Source File
# Begin Source File

SOURCE=.\init.c
# End Source File
# Begin Source File

SOURCE=.\kerberos.c
# End Source File
# Begin Source File

SOURCE=.\limits.c
# End Source File
# Begin Source File

SOURCE=.\lock.c
# End Source File
# Begin Source File

SOURCE=.\matchedValues.c
# End Source File
# Begin Source File

SOURCE=.\modify.c
# End Source File
# Begin Source File

SOURCE=.\modrdn.c
# End Source File
# Begin Source File

SOURCE=.\mods.c
# End Source File
# Begin Source File

SOURCE=.\mr.c
# End Source File
# Begin Source File

SOURCE=.\mra.c
# End Source File
# Begin Source File

SOURCE=.\oc.c
# End Source File
# Begin Source File

SOURCE=.\oidm.c
# End Source File
# Begin Source File

SOURCE=.\operation.c
# End Source File
# Begin Source File

SOURCE=.\passwd.c
# End Source File
# Begin Source File

SOURCE=.\phonetic.c
# End Source File
# Begin Source File

SOURCE=".\proto-slap.h"
# End Source File
# Begin Source File

SOURCE=.\referral.c
# End Source File
# Begin Source File

SOURCE=.\repl.c
# End Source File
# Begin Source File

SOURCE=.\root_dse.c
# End Source File
# Begin Source File

SOURCE=.\sasl.c
# End Source File
# Begin Source File

SOURCE=.\saslauthz.c
# End Source File
# Begin Source File

SOURCE=.\schema.c
# End Source File
# Begin Source File

SOURCE=.\schema_check.c
# End Source File
# Begin Source File

SOURCE=.\schema_init.c
# End Source File
# Begin Source File

SOURCE=.\schema_prep.c
# End Source File
# Begin Source File

SOURCE=.\schemaparse.c
# End Source File
# Begin Source File

SOURCE=.\search.c
# End Source File
# Begin Source File

SOURCE=.\sets.c
# End Source File
# Begin Source File

SOURCE=.\sets.h
# End Source File
# Begin Source File

SOURCE=.\slap.h
# End Source File
# Begin Source File

SOURCE=.\starttls.c
# End Source File
# Begin Source File

SOURCE=.\str2filter.c
# End Source File
# Begin Source File

SOURCE=.\syntax.c
# End Source File
# Begin Source File

SOURCE=.\unbind.c
# End Source File
# Begin Source File

SOURCE=.\user.c
# End Source File
# Begin Source File

SOURCE=.\value.c
# End Source File
# End Target
# End Project

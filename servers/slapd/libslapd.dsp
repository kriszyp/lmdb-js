# Microsoft Developer Studio Project File - Name="libslapd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libslapd - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libslapd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libslapd.mak" CFG="libslapd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libslapd - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libslapd - Win32 Debug" (based on "Win32 (x86) Static Library")
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
# PROP Output_Dir "libslapd"
# PROP Intermediate_Dir "libslapd"
# PROP Target_Dir ""
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
# PROP Output_Dir "libslap0"
# PROP Intermediate_Dir "libslap0"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
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

SOURCE=.\add.c
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

SOURCE=.\bind.c
# End Source File
# Begin Source File

SOURCE=.\ch_malloc.c
# End Source File
# Begin Source File

SOURCE=.\charray.c
# End Source File
# Begin Source File

SOURCE=.\compare.c
# End Source File
# Begin Source File

SOURCE=.\config.c
# End Source File
# Begin Source File

SOURCE=.\configinfo.c
# End Source File
# Begin Source File

SOURCE=.\connection.c
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

SOURCE=.\filter.c
# End Source File
# Begin Source File

SOURCE=.\filterentry.c
# End Source File
# Begin Source File

SOURCE=.\init.c
# End Source File
# Begin Source File

SOURCE=.\lock.c
# End Source File
# Begin Source File

SOURCE=.\modify.c
# End Source File
# Begin Source File

SOURCE=.\modrdn.c
# End Source File
# Begin Source File

SOURCE=.\monitor.c
# End Source File
# Begin Source File

SOURCE=.\nt_debug.c
# End Source File
# Begin Source File

SOURCE=.\operation.c
# End Source File
# Begin Source File

SOURCE=.\phonetic.c
# End Source File
# Begin Source File

SOURCE=.\repl.c
# End Source File
# Begin Source File

SOURCE=.\schema.c
# End Source File
# Begin Source File

SOURCE=.\schemaparse.c
# End Source File
# Begin Source File

SOURCE=.\search.c
# End Source File
# Begin Source File

SOURCE=.\str2filter.c
# End Source File
# Begin Source File

SOURCE=.\suffixalias.c
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
# Begin Source File

SOURCE=.\Version.c
# End Source File
# End Target
# End Project

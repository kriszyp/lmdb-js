# Microsoft Developer Studio Project File - Name="backldbm" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=backldbm - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "backldbm.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "backldbm.mak" CFG="backldbm - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "backldbm - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "backldbm - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "backldbm - Win32 Single Debug" (based on\
 "Win32 (x86) Static Library")
!MESSAGE "backldbm - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "backldbm - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\Release"
# PROP Intermediate_Dir "..\..\..\Release\backldbm"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backldbm - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\Debug"
# PROP Intermediate_Dir "..\..\..\Debug\backldbm"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backldbm - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "backldbm"
# PROP BASE Intermediate_Dir "backldbm"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\SDebug"
# PROP Intermediate_Dir "..\..\..\SDebug\backldbm"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backldbm - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "backldb0"
# PROP BASE Intermediate_Dir "backldb0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\SRelease"
# PROP Intermediate_Dir "..\..\..\SRelease\backldbm"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "backldbm - Win32 Release"
# Name "backldbm - Win32 Debug"
# Name "backldbm - Win32 Single Debug"
# Name "backldbm - Win32 Single Release"
# Begin Source File

SOURCE=.\add.c
# End Source File
# Begin Source File

SOURCE=.\alias.c
# End Source File
# Begin Source File

SOURCE=.\attr.c
# End Source File
# Begin Source File

SOURCE=.\attribute.c
# End Source File
# Begin Source File

SOURCE=".\back-ldbm.h"
# End Source File
# Begin Source File

SOURCE=.\bind.c
# End Source File
# Begin Source File

SOURCE=.\cache.c
# End Source File
# Begin Source File

SOURCE=.\close.c
# End Source File
# Begin Source File

SOURCE=.\compare.c
# End Source File
# Begin Source File

SOURCE=.\config.c
# End Source File
# Begin Source File

SOURCE=.\dbcache.c
# End Source File
# Begin Source File

SOURCE=.\delete.c
# End Source File
# Begin Source File

SOURCE=.\dn2id.c
# End Source File
# Begin Source File

SOURCE=.\entry.c
# End Source File
# Begin Source File

SOURCE=.\extended.c
# End Source File
# Begin Source File

SOURCE=.\external.h
# End Source File
# Begin Source File

SOURCE=.\filterindex.c
# End Source File
# Begin Source File

SOURCE=.\group.c
# End Source File
# Begin Source File

SOURCE=.\id2children.c
# End Source File
# Begin Source File

SOURCE=.\id2entry.c
# End Source File
# Begin Source File

SOURCE=.\idl.c
# End Source File
# Begin Source File

SOURCE=.\index.c
# End Source File
# Begin Source File

SOURCE=.\init.c
# End Source File
# Begin Source File

SOURCE=.\key.c
# End Source File
# Begin Source File

SOURCE=.\modify.c
# End Source File
# Begin Source File

SOURCE=.\modrdn.c
# End Source File
# Begin Source File

SOURCE=.\nextid.c
# End Source File
# Begin Source File

SOURCE=.\operational.c
# End Source File
# Begin Source File

SOURCE=.\passwd.c
# End Source File
# Begin Source File

SOURCE=".\proto-back-ldbm.h"
# End Source File
# Begin Source File

SOURCE=.\referral.c
# End Source File
# Begin Source File

SOURCE=.\search.c
# End Source File
# Begin Source File

SOURCE=.\tools.c
# End Source File
# End Target
# End Project

# Microsoft Developer Studio Project File - Name="libldif" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libldif - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libldif.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libldif.mak" CFG="libldif - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libldif - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libldif - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libldif - Win32 Single Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libldif - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "libldif - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\libldif"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Release\oldif32.lib"

!ELSEIF  "$(CFG)" == "libldif - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\libldif"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Debug\oldif32.lib"

!ELSEIF  "$(CFG)" == "libldif - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libldif_"
# PROP BASE Intermediate_Dir "libldif_"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\libldif"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Debug\oldif32.lib"
# ADD LIB32 /nologo /out:"..\..\SDebug\oldif32.lib"

!ELSEIF  "$(CFG)" == "libldif - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libldif0"
# PROP BASE Intermediate_Dir "libldif0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\libldif"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Release\oldif32.lib"
# ADD LIB32 /nologo /out:"..\..\SRelease\oldif32.lib"

!ENDIF 

# Begin Target

# Name "libldif - Win32 Release"
# Name "libldif - Win32 Debug"
# Name "libldif - Win32 Single Debug"
# Name "libldif - Win32 Single Release"
# Begin Source File

SOURCE=.\fetch.c
# End Source File
# Begin Source File

SOURCE=..\..\include\ldif.h
# End Source File
# Begin Source File

SOURCE=.\line64.c
# End Source File
# End Target
# End Project

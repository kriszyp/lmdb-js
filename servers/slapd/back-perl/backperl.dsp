# Microsoft Developer Studio Project File - Name="backperl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=backperl - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "backperl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "backperl.mak" CFG="backperl - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "backperl - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "backperl - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "backperl - Win32 Single Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "backperl - Win32 Single Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "backperl - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\Release"
# PROP Intermediate_Dir "..\..\..\Release\backperl"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_CONSOLE" /D "NO_STRICT" /D "HAVE_DES_CRYPT" /D "PERL_IMPLICIT_CONTEXT" /D "PERL_IMPLICIT_SYS" /D "PERL_MSVCRT_READFIX" /D "MULTIPLICITY" /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backperl - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\Debug"
# PROP Intermediate_Dir "..\..\..\Debug\backperl"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "PERL_IMPLICIT_CONTEXT" /D "PERL_IMPLICIT_SYS" /D "NO_STRICT" /D "HAVE_DES_FCRYPT" /D "PERL_MSVCRT_READFIX" /FR /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backperl - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "backperl"
# PROP BASE Intermediate_Dir "backperl"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\SDebug"
# PROP Intermediate_Dir "..\..\..\SDebug\backperl"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\\" /I "..\..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "backperl - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "backldb0"
# PROP BASE Intermediate_Dir "backldb0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\SRelease"
# PROP Intermediate_Dir "..\..\..\SRelease\backperl"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "D:\perl\lib\CORE" /I "..\\" /I "..\..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_CONSOLE" /D "NO_STRICT" /D "HAVE_DES_FCRYPT" /D "PERL_IMPLICIT_CONTEXT" /D "PERL_IMPLICIT_SYS" /D "PERL_MSVCRT_READFIX" /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "backperl - Win32 Release"
# Name "backperl - Win32 Debug"
# Name "backperl - Win32 Single Debug"
# Name "backperl - Win32 Single Release"
# Begin Source File

SOURCE=.\add.c
# End Source File
# Begin Source File

SOURCE=.\asperl_undefs.h
# End Source File
# Begin Source File

SOURCE=.\bind.c
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

SOURCE=.\delete.c
# End Source File
# Begin Source File

SOURCE=.\external.h
# End Source File
# Begin Source File

SOURCE=.\init.c
# End Source File
# Begin Source File

SOURCE=.\modify.c
# End Source File
# Begin Source File

SOURCE=.\modrdn.c
# End Source File
# Begin Source File

SOURCE=.\perl_back.h
# End Source File
# Begin Source File

SOURCE=.\search.c
# End Source File
# End Target
# End Project

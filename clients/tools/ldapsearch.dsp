# Microsoft Developer Studio Project File - Name="ldapsearch" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=ldapsearch - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ldapsearch.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ldapsearch.mak" CFG="ldapsearch - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ldapsearch - Win32 Single Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapsearch - Win32 Single Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapsearch - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapsearch - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ldapsearch - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ldapsear"
# PROP BASE Intermediate_Dir "ldapsear"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\ldapsearch"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 oldap32.lib olber32.lib oldif32.lib olutil32.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 libsasl.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\..\SDebug"

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ldapsea0"
# PROP BASE Intermediate_Dir "ldapsea0"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\ldapsearch"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 oldap32.lib olber32.lib oldif32.lib olutil32.lib ws2_32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 sasl.lib libsasl.lib ws2_32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\..\SRelease"

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ldapsea1"
# PROP BASE Intermediate_Dir "ldapsea1"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\ldapsearch"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 sasl.lib libsasl.lib ws2_32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\..\Release"

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ldapsea2"
# PROP BASE Intermediate_Dir "ldapsea2"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\ldapsearch"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MTd /W2 /GX /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 libsasl.lib ws2_32.lib /nologo /subsystem:console /incremental:yes /debug /machine:I386 /libpath:"..\..\Debug"

!ENDIF 

# Begin Target

# Name "ldapsearch - Win32 Single Debug"
# Name "ldapsearch - Win32 Single Release"
# Name "ldapsearch - Win32 Release"
# Name "ldapsearch - Win32 Debug"
# Begin Source File

SOURCE=.\common.c
# End Source File
# Begin Source File

SOURCE=.\ldapsearch.c
# End Source File
# Begin Source File

SOURCE=.\ldsversion.c
# End Source File
# Begin Source File

SOURCE=..\..\build\version.h

USERDEP__VERSI="common.c"	"ldapsearch.c"	"$(OUTDIR)\oldap32.lib"	"$(OUTDIR)\olber32.lib"	"$(OUTDIR)\oldif32.lib"	"$(OUTDIR)\olutil32.lib"
InputDir=..\..\build
InputPath=..\..\build\version.h

!IF  "$(CFG)" == "ldapsearch - Win32 Single Debug"

# Begin Custom Build

"ldsversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldsversion.c ldapsearch /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Single Release"

# Begin Custom Build

"ldsversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldsversion.c ldapsearch /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Release"

# Begin Custom Build

"ldsversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldsversion.c ldapsearch /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapsearch - Win32 Debug"

# Begin Custom Build

"ldsversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldsversion.c ldapsearch /**/

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project

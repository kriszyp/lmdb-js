# Microsoft Developer Studio Project File - Name="ldapmodrdn" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=ldapmodrdn - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ldapmodrdn.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ldapmodrdn.mak" CFG="ldapmodrdn - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ldapmodrdn - Win32 Single Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapmodrdn - Win32 Single Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapmodrdn - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ldapmodrdn - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ldapmodrdn - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ldapmodr"
# PROP BASE Intermediate_Dir "ldapmodr"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\ldapmodrdn"
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
# ADD BASE LINK32 oldap32.lib olber32.lib olutil32.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 libsasl.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\..\SDebug"

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ldapmod0"
# PROP BASE Intermediate_Dir "ldapmod0"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\ldapmodrdn"
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
# ADD BASE LINK32 oldap32.lib olber32.lib olutil32.lib ws2_32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 sasl.lib libsasl.lib ws2_32.lib /nologo /subsystem:console /machine:I386 /libpath:"..\..\SRelease"

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ldapmod1"
# PROP BASE Intermediate_Dir "ldapmod1"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\ldapmodrdn"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR /YX /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 libsasl.lib ws2_32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept /libpath:"..\..\Debug"

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ldapmod2"
# PROP BASE Intermediate_Dir "ldapmod2"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\ldapmodrdn"
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

!ENDIF 

# Begin Target

# Name "ldapmodrdn - Win32 Single Debug"
# Name "ldapmodrdn - Win32 Single Release"
# Name "ldapmodrdn - Win32 Debug"
# Name "ldapmodrdn - Win32 Release"
# Begin Source File

SOURCE=.\common.c
# End Source File
# Begin Source File

SOURCE=.\ldapmodrdn.c
# End Source File
# Begin Source File

SOURCE=.\ldrversion.c
# End Source File
# Begin Source File

SOURCE=..\..\build\version.h

USERDEP__VERSI="common.c"	"ldapmodrdn.c"	"$(OUTDIR)\oldap32.lib"	"$(OUTDIR)\olber32.lib"	"$(OUTDIR)\olutil32.lib"
InputDir=..\..\build
InputPath=..\..\build\version.h

!IF  "$(CFG)" == "ldapmodrdn - Win32 Single Debug"

# Begin Custom Build

"ldrversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldrversion.c ldapmodrdn /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Single Release"

# Begin Custom Build

"ldrversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldrversion.c ldapmodrdn /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Release"

# Begin Custom Build

"ldrversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldrversion.c ldapmodrdn /**/

# End Custom Build

!ELSEIF  "$(CFG)" == "ldapmodrdn - Win32 Debug"

# Begin Custom Build

"ldrversion.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	$(InputDir)\mkvers.bat $(InputPath) ldrversion.c ldapmodrdn /**/

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project

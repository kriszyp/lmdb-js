# Microsoft Developer Studio Project File - Name="liblutil" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=liblutil - Win32 Single Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "liblutil.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "liblutil.mak" CFG="liblutil - Win32 Single Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "liblutil - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "liblutil - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "liblutil - Win32 Single Debug" (based on\
 "Win32 (x86) Static Library")
!MESSAGE "liblutil - Win32 Single Release" (based on\
 "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "liblutil - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\Release"
# PROP Intermediate_Dir "..\..\Release\liblutil"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Release\olutil32.lib"

!ELSEIF  "$(CFG)" == "liblutil - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\Debug"
# PROP Intermediate_Dir "..\..\Debug\liblutil"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\Debug\olutil32.lib"

!ELSEIF  "$(CFG)" == "liblutil - Win32 Single Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "liblutil"
# PROP BASE Intermediate_Dir "liblutil"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\SDebug"
# PROP Intermediate_Dir "..\..\SDebug\liblutil"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /MTd /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /Z7 /Od /I "..\..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Debug\olutil32.lib"
# ADD LIB32 /nologo /out:"..\..\SDebug\olutil32.lib"

!ELSEIF  "$(CFG)" == "liblutil - Win32 Single Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libluti0"
# PROP BASE Intermediate_Dir "libluti0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\SRelease"
# PROP Intermediate_Dir "..\..\SRelease\liblutil"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /GX /O2 /I "..\..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\Release\olutil32.lib"
# ADD LIB32 /nologo /out:"..\..\SRelease\olutil32.lib"

!ENDIF 

# Begin Target

# Name "liblutil - Win32 Release"
# Name "liblutil - Win32 Debug"
# Name "liblutil - Win32 Single Debug"
# Name "liblutil - Win32 Single Release"
# Begin Source File

SOURCE=.\authpasswd.c
# End Source File
# Begin Source File

SOURCE=.\base64.c
# End Source File
# Begin Source File

SOURCE=..\..\include\ac\bytes.h
# End Source File
# Begin Source File

SOURCE=.\csn.c
# End Source File
# Begin Source File

SOURCE=.\debug.c
# End Source File
# Begin Source File

SOURCE=.\entropy.c
# End Source File
# Begin Source File

SOURCE="..\..\include\getopt-compat.h"
# End Source File
# Begin Source File

SOURCE=.\getopt.c
# End Source File
# Begin Source File

SOURCE=.\getpass.c
# End Source File
# Begin Source File

SOURCE=.\hash.c
# End Source File
# Begin Source File

SOURCE=..\..\include\ldap_cdefs.h
# End Source File
# Begin Source File

SOURCE=.\lockf.c
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil.h
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil_hash.h
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil_ldap.h
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil_lockf.h
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil_md5.h
# End Source File
# Begin Source File

SOURCE=..\..\include\lutil_sha1.h
# End Source File
# Begin Source File

SOURCE=.\md5.c
# End Source File
# Begin Source File

SOURCE=.\ntservice.c
# End Source File
# Begin Source File

SOURCE=.\passwd.c
# End Source File
# Begin Source File

SOURCE=..\..\include\portable.h
# End Source File
# Begin Source File

SOURCE="..\..\include\queue-compat.h"
# End Source File
# Begin Source File

SOURCE=.\sasl.c
# End Source File
# Begin Source File

SOURCE=.\sha1.c
# End Source File
# Begin Source File

SOURCE=.\slapdmsg.mc

!IF  "$(CFG)" == "liblutil - Win32 Release"

# Begin Custom Build - Building slapd message file
IntDir=.\..\..\Release\liblutil
InputPath=.\slapdmsg.mc

"slapdmsg.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir $(IntDir) 
	mc -v slapdmsg.mc -r $(IntDir) 
	rc /v /r $(IntDir)\slapdmsg.rc 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "liblutil - Win32 Debug"

# Begin Custom Build - Building slapd message file
IntDir=.\..\..\Debug\liblutil
InputPath=.\slapdmsg.mc

"slapdmsg.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir $(IntDir) 
	mc -v slapdmsg.mc -r $(IntDir) 
	rc /v /r $(IntDir)\slapdmsg.rc 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "liblutil - Win32 Single Debug"

# Begin Custom Build - Building slapd message file
IntDir=.\..\..\SDebug\liblutil
InputPath=.\slapdmsg.mc

"slapdmsg.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir $(IntDir) 
	mc -v slapdmsg.mc -r $(IntDir) 
	rc /v /r $(IntDir)\slapdmsg.rc 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "liblutil - Win32 Single Release"

# Begin Custom Build - Building slapd message file
IntDir=.\..\..\SRelease\liblutil
InputPath=.\slapdmsg.mc

"slapdmsg.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	mkdir $(IntDir) 
	mc -v slapdmsg.mc -r $(IntDir) 
	rc /v /r $(IntDir)\slapdmsg.rc 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sockpair.c
# End Source File
# Begin Source File

SOURCE=.\utils.c
# End Source File
# Begin Source File

SOURCE=.\uuid.c
# End Source File
# End Target
# End Project

# Microsoft Developer Studio Generated NMAKE File, Format Version 4.10
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

!IF "$(CFG)" == ""
CFG=LTEST - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to LTEST - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "LTEST - Win32 Release" && "$(CFG)" != "LTEST - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "LTEST32.MAK" CFG="LTEST - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "LTEST - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "LTEST - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "LTEST - Win32 Debug"
CPP=cl.exe
RSC=rc.exe
MTL=mktyplib.exe

!IF  "$(CFG)" == "LTEST - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\LTEST32.exe"

CLEAN : 
	-@erase "$(INTDIR)\console.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\ltest.res"
	-@erase "$(INTDIR)\test.obj"
	-@erase "$(INTDIR)\textwind.obj"
	-@erase "$(OUTDIR)\LTEST32.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /O1 /I "..\winsock" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /FR /YX /c
# ADD CPP /nologo /W3 /O1 /I "..\..\..\..\include" /I "." /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /YX /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /ML /W3 /O1 /I "..\..\..\..\include" /I "." /D "WIN32" /D\
 "NDEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK"\
 /Fp"$(INTDIR)/LTEST32.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/ltest.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/LTEST32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows /machine:IX86
# ADD LINK32 oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows /machine:IX86
LINK32_FLAGS=oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows\
 /incremental:no /pdb:"$(OUTDIR)/LTEST32.pdb" /machine:IX86 /def:".\ltest.def"\
 /out:"$(OUTDIR)/LTEST32.exe" 
DEF_FILE= \
	".\ltest.def"
LINK32_OBJS= \
	"$(INTDIR)\console.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\ltest.res" \
	"$(INTDIR)\test.obj" \
	"$(INTDIR)\textwind.obj" \
	"..\..\..\..\..\..\MSDEV\LIB\WSOCK32.LIB" \
	"..\..\..\libldap\Debug\ldap32.lib"

"$(OUTDIR)\LTEST32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\LTEST32.exe"

CLEAN : 
	-@erase "$(INTDIR)\console.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\ltest.res"
	-@erase "$(INTDIR)\test.obj"
	-@erase "$(INTDIR)\textwind.obj"
	-@erase "$(OUTDIR)\LTEST32.exe"
	-@erase "$(OUTDIR)\LTEST32.ilk"
	-@erase "$(OUTDIR)\LTEST32.pdb"
	-@erase ".\LIBLDAP.IDB"
	-@erase ".\LIBLDAP.PDB"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /Zi /Od /Gf /I "..\h" /I "..\winsock" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /FR /YX /Fd"LIBLDAP.PDB" /c
# ADD CPP /nologo /W3 /Gm /Zi /Od /Gf /I "..\h" /I "..\..\..\..\include" /I "." /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /YX /Fd"LIBLDAP.PDB" /c
# SUBTRACT CPP /Fr
CPP_PROJ=/nologo /MLd /W3 /Gm /Zi /Od /Gf /I "..\h" /I "..\..\..\..\include" /I\
 "." /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK"\
 /Fp"$(INTDIR)/LTEST32.pch" /YX /Fo"$(INTDIR)/" /Fd"LIBLDAP.PDB" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/ltest.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/LTEST32.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows /debug /machine:IX86
# ADD LINK32 oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows /debug /machine:IX86
LINK32_FLAGS=oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /stack:0x2800 /subsystem:windows\
 /incremental:yes /pdb:"$(OUTDIR)/LTEST32.pdb" /debug /machine:IX86\
 /def:".\ltest.def" /out:"$(OUTDIR)/LTEST32.exe" 
DEF_FILE= \
	".\ltest.def"
LINK32_OBJS= \
	"$(INTDIR)\console.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\ltest.res" \
	"$(INTDIR)\test.obj" \
	"$(INTDIR)\textwind.obj" \
	"..\..\..\..\..\..\MSDEV\LIB\WSOCK32.LIB" \
	"..\..\..\libldap\Debug\ldap32.lib"

"$(OUTDIR)\LTEST32.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "LTEST - Win32 Release"
# Name "LTEST - Win32 Debug"

!IF  "$(CFG)" == "LTEST - Win32 Release"

!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\console.c
DEP_CPP_CONSO=\
	".\console.h"\
	

"$(INTDIR)\console.obj" : $(SOURCE) $(DEP_CPP_CONSO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\textwind.c
DEP_CPP_TEXTW=\
	".\console.h"\
	".\textwind.h"\
	

"$(INTDIR)\textwind.obj" : $(SOURCE) $(DEP_CPP_TEXTW) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ltest.rc

!IF  "$(CFG)" == "LTEST - Win32 Release"


"$(INTDIR)\ltest.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

DEP_RSC_LTEST=\
	".\console.h"\
	".\inpdlg.dlg"\
	

"$(INTDIR)\ltest.res" : $(SOURCE) $(DEP_RSC_LTEST) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\macintos\getopt.c"
DEP_CPP_GETOP=\
	"..\..\..\..\include\lber.h"\
	"..\..\..\..\include\proto-lb.h"\
	"..\..\..\..\include\proto-lber.h"\
	

"$(INTDIR)\getopt.obj" : $(SOURCE) $(DEP_CPP_GETOP) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\libldap\test.c"
DEP_CPP_TEST_=\
	"..\..\..\..\include\lber.h"\
	"..\..\..\..\include\ldap.h"\
	"..\..\..\..\include\msdos.h"\
	"..\..\..\..\include\proto-lb.h"\
	"..\..\..\..\include\proto-lber.h"\
	"..\..\..\..\include\proto-ld.h"\
	"..\..\..\..\include\proto-ldap.h"\
	".\console.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_TEST_=\
	"..\..\..\libldap\macos.h"\
	"..\..\..\libldap\msdos.h"\
	

"$(INTDIR)\test.obj" : $(SOURCE) $(DEP_CPP_TEST_) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ltest.def

!IF  "$(CFG)" == "LTEST - Win32 Release"

!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\libldap\Debug\ldap32.lib"

!IF  "$(CFG)" == "LTEST - Win32 Release"

!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\MSDEV\LIB\WSOCK32.LIB

!IF  "$(CFG)" == "LTEST - Win32 Release"

!ELSEIF  "$(CFG)" == "LTEST - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################

# Microsoft Developer Studio Generated NMAKE File, Format Version 4.10
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=libldap - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to libldap - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "libldap - Win32 Release" && "$(CFG)" !=\
 "libldap - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "ldap32.mak" CFG="libldap - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libldap - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libldap - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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
# PROP Target_Last_Scanned "libldap - Win32 Debug"
CPP=cl.exe
RSC=rc.exe
MTL=mktyplib.exe

!IF  "$(CFG)" == "libldap - Win32 Release"

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

ALL : "$(OUTDIR)\ldap32.dll" "$(OUTDIR)\ldap32.bsc"

CLEAN : 
	-@erase "$(INTDIR)\abandon.obj"
	-@erase "$(INTDIR)\abandon.sbr"
	-@erase "$(INTDIR)\add.obj"
	-@erase "$(INTDIR)\add.sbr"
	-@erase "$(INTDIR)\addentry.obj"
	-@erase "$(INTDIR)\addentry.sbr"
	-@erase "$(INTDIR)\bind.obj"
	-@erase "$(INTDIR)\bind.sbr"
	-@erase "$(INTDIR)\cache.obj"
	-@erase "$(INTDIR)\cache.sbr"
	-@erase "$(INTDIR)\charset.obj"
	-@erase "$(INTDIR)\charset.sbr"
	-@erase "$(INTDIR)\compare.obj"
	-@erase "$(INTDIR)\compare.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\delete.obj"
	-@erase "$(INTDIR)\delete.sbr"
	-@erase "$(INTDIR)\disptmpl.obj"
	-@erase "$(INTDIR)\disptmpl.sbr"
	-@erase "$(INTDIR)\dsparse.obj"
	-@erase "$(INTDIR)\dsparse.sbr"
	-@erase "$(INTDIR)\encode.obj"
	-@erase "$(INTDIR)\encode.sbr"
	-@erase "$(INTDIR)\error.obj"
	-@erase "$(INTDIR)\error.sbr"
	-@erase "$(INTDIR)\free.obj"
	-@erase "$(INTDIR)\free.sbr"
	-@erase "$(INTDIR)\friendly.obj"
	-@erase "$(INTDIR)\friendly.sbr"
	-@erase "$(INTDIR)\getattr.obj"
	-@erase "$(INTDIR)\getattr.sbr"
	-@erase "$(INTDIR)\getdn.obj"
	-@erase "$(INTDIR)\getdn.sbr"
	-@erase "$(INTDIR)\getentry.obj"
	-@erase "$(INTDIR)\getentry.sbr"
	-@erase "$(INTDIR)\getfilte.obj"
	-@erase "$(INTDIR)\getfilte.sbr"
	-@erase "$(INTDIR)\getvalue.obj"
	-@erase "$(INTDIR)\getvalue.sbr"
	-@erase "$(INTDIR)\io.obj"
	-@erase "$(INTDIR)\io.sbr"
	-@erase "$(INTDIR)\kbind.obj"
	-@erase "$(INTDIR)\kbind.sbr"
	-@erase "$(INTDIR)\kerberos.obj"
	-@erase "$(INTDIR)\kerberos.sbr"
	-@erase "$(INTDIR)\libldap.res"
	-@erase "$(INTDIR)\modify.obj"
	-@erase "$(INTDIR)\modify.sbr"
	-@erase "$(INTDIR)\modrdn.obj"
	-@erase "$(INTDIR)\modrdn.sbr"
	-@erase "$(INTDIR)\msdos.obj"
	-@erase "$(INTDIR)\msdos.sbr"
	-@erase "$(INTDIR)\open.obj"
	-@erase "$(INTDIR)\open.sbr"
	-@erase "$(INTDIR)\regex.obj"
	-@erase "$(INTDIR)\regex.sbr"
	-@erase "$(INTDIR)\request.obj"
	-@erase "$(INTDIR)\request.sbr"
	-@erase "$(INTDIR)\result.obj"
	-@erase "$(INTDIR)\result.sbr"
	-@erase "$(INTDIR)\sbind.obj"
	-@erase "$(INTDIR)\sbind.sbr"
	-@erase "$(INTDIR)\search.obj"
	-@erase "$(INTDIR)\search.sbr"
	-@erase "$(INTDIR)\sort.obj"
	-@erase "$(INTDIR)\sort.sbr"
	-@erase "$(INTDIR)\srchpref.obj"
	-@erase "$(INTDIR)\srchpref.sbr"
	-@erase "$(INTDIR)\tmplout.obj"
	-@erase "$(INTDIR)\tmplout.sbr"
	-@erase "$(INTDIR)\ufn.obj"
	-@erase "$(INTDIR)\ufn.sbr"
	-@erase "$(INTDIR)\unbind.obj"
	-@erase "$(INTDIR)\unbind.sbr"
	-@erase "$(INTDIR)\url.obj"
	-@erase "$(INTDIR)\url.sbr"
	-@erase "$(INTDIR)\wsockip.obj"
	-@erase "$(INTDIR)\wsockip.sbr"
	-@erase "$(OUTDIR)\ldap32.bsc"
	-@erase "$(OUTDIR)\ldap32.dll"
	-@erase "$(OUTDIR)\ldap32.exp"
	-@erase "$(OUTDIR)\ldap32.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /G3 /MT /W3 /Od /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "KERBEROS" /YX /c
# ADD CPP /nologo /G3 /MT /W3 /Od /I "..\..\include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "_NODLLIMPORT_" /FR /YX /c
CPP_PROJ=/nologo /G3 /MT /W3 /Od /I "..\..\include" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D\
 "_NODLLIMPORT_" /FR"$(INTDIR)/" /Fp"$(INTDIR)/ldap32.pch" /YX /Fo"$(INTDIR)/"\
 /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\Release/
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/libldap.res" /d "NDEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ldap32.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\abandon.sbr" \
	"$(INTDIR)\add.sbr" \
	"$(INTDIR)\addentry.sbr" \
	"$(INTDIR)\bind.sbr" \
	"$(INTDIR)\cache.sbr" \
	"$(INTDIR)\charset.sbr" \
	"$(INTDIR)\compare.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\delete.sbr" \
	"$(INTDIR)\disptmpl.sbr" \
	"$(INTDIR)\dsparse.sbr" \
	"$(INTDIR)\encode.sbr" \
	"$(INTDIR)\error.sbr" \
	"$(INTDIR)\free.sbr" \
	"$(INTDIR)\friendly.sbr" \
	"$(INTDIR)\getattr.sbr" \
	"$(INTDIR)\getdn.sbr" \
	"$(INTDIR)\getentry.sbr" \
	"$(INTDIR)\getfilte.sbr" \
	"$(INTDIR)\getvalue.sbr" \
	"$(INTDIR)\io.sbr" \
	"$(INTDIR)\kbind.sbr" \
	"$(INTDIR)\kerberos.sbr" \
	"$(INTDIR)\modify.sbr" \
	"$(INTDIR)\modrdn.sbr" \
	"$(INTDIR)\msdos.sbr" \
	"$(INTDIR)\open.sbr" \
	"$(INTDIR)\regex.sbr" \
	"$(INTDIR)\request.sbr" \
	"$(INTDIR)\result.sbr" \
	"$(INTDIR)\sbind.sbr" \
	"$(INTDIR)\search.sbr" \
	"$(INTDIR)\sort.sbr" \
	"$(INTDIR)\srchpref.sbr" \
	"$(INTDIR)\tmplout.sbr" \
	"$(INTDIR)\ufn.sbr" \
	"$(INTDIR)\unbind.sbr" \
	"$(INTDIR)\url.sbr" \
	"$(INTDIR)\wsockip.sbr"

"$(OUTDIR)\ldap32.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 oldnames.lib ldllcew.lib krbv4win.lib wshelper.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /map:"FULL" /machine:IX86
# ADD LINK32 WSOCK32.LIB oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:IX86
# SUBTRACT LINK32 /map
LINK32_FLAGS=WSOCK32.LIB oldnames.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/ldap32.pdb" /machine:IX86\
 /out:"$(OUTDIR)/ldap32.dll" /implib:"$(OUTDIR)/ldap32.lib" 
LINK32_OBJS= \
	"$(INTDIR)\abandon.obj" \
	"$(INTDIR)\add.obj" \
	"$(INTDIR)\addentry.obj" \
	"$(INTDIR)\bind.obj" \
	"$(INTDIR)\cache.obj" \
	"$(INTDIR)\charset.obj" \
	"$(INTDIR)\compare.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\delete.obj" \
	"$(INTDIR)\disptmpl.obj" \
	"$(INTDIR)\dsparse.obj" \
	"$(INTDIR)\encode.obj" \
	"$(INTDIR)\error.obj" \
	"$(INTDIR)\free.obj" \
	"$(INTDIR)\friendly.obj" \
	"$(INTDIR)\getattr.obj" \
	"$(INTDIR)\getdn.obj" \
	"$(INTDIR)\getentry.obj" \
	"$(INTDIR)\getfilte.obj" \
	"$(INTDIR)\getvalue.obj" \
	"$(INTDIR)\io.obj" \
	"$(INTDIR)\kbind.obj" \
	"$(INTDIR)\kerberos.obj" \
	"$(INTDIR)\libldap.res" \
	"$(INTDIR)\modify.obj" \
	"$(INTDIR)\modrdn.obj" \
	"$(INTDIR)\msdos.obj" \
	"$(INTDIR)\open.obj" \
	"$(INTDIR)\regex.obj" \
	"$(INTDIR)\request.obj" \
	"$(INTDIR)\result.obj" \
	"$(INTDIR)\sbind.obj" \
	"$(INTDIR)\search.obj" \
	"$(INTDIR)\sort.obj" \
	"$(INTDIR)\srchpref.obj" \
	"$(INTDIR)\tmplout.obj" \
	"$(INTDIR)\ufn.obj" \
	"$(INTDIR)\unbind.obj" \
	"$(INTDIR)\url.obj" \
	"$(INTDIR)\wsockip.obj" \
	"..\..\..\..\MSDEV\LIB\WSOCK32.LIB"

"$(OUTDIR)\ldap32.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "libldap - Win32 Debug"

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

ALL : "$(OUTDIR)\ldap32.dll" "$(OUTDIR)\ldap32.bsc"

CLEAN : 
	-@erase "$(INTDIR)\abandon.obj"
	-@erase "$(INTDIR)\abandon.sbr"
	-@erase "$(INTDIR)\add.obj"
	-@erase "$(INTDIR)\add.sbr"
	-@erase "$(INTDIR)\addentry.obj"
	-@erase "$(INTDIR)\addentry.sbr"
	-@erase "$(INTDIR)\bind.obj"
	-@erase "$(INTDIR)\bind.sbr"
	-@erase "$(INTDIR)\cache.obj"
	-@erase "$(INTDIR)\cache.sbr"
	-@erase "$(INTDIR)\charset.obj"
	-@erase "$(INTDIR)\charset.sbr"
	-@erase "$(INTDIR)\compare.obj"
	-@erase "$(INTDIR)\compare.sbr"
	-@erase "$(INTDIR)\decode.obj"
	-@erase "$(INTDIR)\decode.sbr"
	-@erase "$(INTDIR)\delete.obj"
	-@erase "$(INTDIR)\delete.sbr"
	-@erase "$(INTDIR)\disptmpl.obj"
	-@erase "$(INTDIR)\disptmpl.sbr"
	-@erase "$(INTDIR)\dsparse.obj"
	-@erase "$(INTDIR)\dsparse.sbr"
	-@erase "$(INTDIR)\encode.obj"
	-@erase "$(INTDIR)\encode.sbr"
	-@erase "$(INTDIR)\error.obj"
	-@erase "$(INTDIR)\error.sbr"
	-@erase "$(INTDIR)\free.obj"
	-@erase "$(INTDIR)\free.sbr"
	-@erase "$(INTDIR)\friendly.obj"
	-@erase "$(INTDIR)\friendly.sbr"
	-@erase "$(INTDIR)\getattr.obj"
	-@erase "$(INTDIR)\getattr.sbr"
	-@erase "$(INTDIR)\getdn.obj"
	-@erase "$(INTDIR)\getdn.sbr"
	-@erase "$(INTDIR)\getentry.obj"
	-@erase "$(INTDIR)\getentry.sbr"
	-@erase "$(INTDIR)\getfilte.obj"
	-@erase "$(INTDIR)\getfilte.sbr"
	-@erase "$(INTDIR)\getvalue.obj"
	-@erase "$(INTDIR)\getvalue.sbr"
	-@erase "$(INTDIR)\io.obj"
	-@erase "$(INTDIR)\io.sbr"
	-@erase "$(INTDIR)\kbind.obj"
	-@erase "$(INTDIR)\kbind.sbr"
	-@erase "$(INTDIR)\kerberos.obj"
	-@erase "$(INTDIR)\kerberos.sbr"
	-@erase "$(INTDIR)\libldap.res"
	-@erase "$(INTDIR)\modify.obj"
	-@erase "$(INTDIR)\modify.sbr"
	-@erase "$(INTDIR)\modrdn.obj"
	-@erase "$(INTDIR)\modrdn.sbr"
	-@erase "$(INTDIR)\msdos.obj"
	-@erase "$(INTDIR)\msdos.sbr"
	-@erase "$(INTDIR)\open.obj"
	-@erase "$(INTDIR)\open.sbr"
	-@erase "$(INTDIR)\regex.obj"
	-@erase "$(INTDIR)\regex.sbr"
	-@erase "$(INTDIR)\request.obj"
	-@erase "$(INTDIR)\request.sbr"
	-@erase "$(INTDIR)\result.obj"
	-@erase "$(INTDIR)\result.sbr"
	-@erase "$(INTDIR)\sbind.obj"
	-@erase "$(INTDIR)\sbind.sbr"
	-@erase "$(INTDIR)\search.obj"
	-@erase "$(INTDIR)\search.sbr"
	-@erase "$(INTDIR)\sort.obj"
	-@erase "$(INTDIR)\sort.sbr"
	-@erase "$(INTDIR)\srchpref.obj"
	-@erase "$(INTDIR)\srchpref.sbr"
	-@erase "$(INTDIR)\tmplout.obj"
	-@erase "$(INTDIR)\tmplout.sbr"
	-@erase "$(INTDIR)\ufn.obj"
	-@erase "$(INTDIR)\ufn.sbr"
	-@erase "$(INTDIR)\unbind.obj"
	-@erase "$(INTDIR)\unbind.sbr"
	-@erase "$(INTDIR)\url.obj"
	-@erase "$(INTDIR)\url.sbr"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(INTDIR)\wsockip.obj"
	-@erase "$(INTDIR)\wsockip.sbr"
	-@erase "$(OUTDIR)\ldap32.bsc"
	-@erase "$(OUTDIR)\ldap32.dll"
	-@erase "$(OUTDIR)\ldap32.exp"
	-@erase "$(OUTDIR)\ldap32.ilk"
	-@erase "$(OUTDIR)\ldap32.lib"
	-@erase "$(OUTDIR)\ldap32.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /Zi /Od /Gf /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "KERBEROS" /FR /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /Zi /Od /Gf /I "..\..\include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "_NODLLIMPORT_" /FR /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /Zi /Od /Gf /I "..\..\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D\
 "NO_USERINTERFACE" /D "_NODLLIMPORT_" /FR"$(INTDIR)/" /Fp"$(INTDIR)/ldap32.pch"\
 /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\Debug/
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
RSC_PROJ=/l 0x409 /fo"$(INTDIR)/libldap.res" /d "_DEBUG" 
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ldap32.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\abandon.sbr" \
	"$(INTDIR)\add.sbr" \
	"$(INTDIR)\addentry.sbr" \
	"$(INTDIR)\bind.sbr" \
	"$(INTDIR)\cache.sbr" \
	"$(INTDIR)\charset.sbr" \
	"$(INTDIR)\compare.sbr" \
	"$(INTDIR)\decode.sbr" \
	"$(INTDIR)\delete.sbr" \
	"$(INTDIR)\disptmpl.sbr" \
	"$(INTDIR)\dsparse.sbr" \
	"$(INTDIR)\encode.sbr" \
	"$(INTDIR)\error.sbr" \
	"$(INTDIR)\free.sbr" \
	"$(INTDIR)\friendly.sbr" \
	"$(INTDIR)\getattr.sbr" \
	"$(INTDIR)\getdn.sbr" \
	"$(INTDIR)\getentry.sbr" \
	"$(INTDIR)\getfilte.sbr" \
	"$(INTDIR)\getvalue.sbr" \
	"$(INTDIR)\io.sbr" \
	"$(INTDIR)\kbind.sbr" \
	"$(INTDIR)\kerberos.sbr" \
	"$(INTDIR)\modify.sbr" \
	"$(INTDIR)\modrdn.sbr" \
	"$(INTDIR)\msdos.sbr" \
	"$(INTDIR)\open.sbr" \
	"$(INTDIR)\regex.sbr" \
	"$(INTDIR)\request.sbr" \
	"$(INTDIR)\result.sbr" \
	"$(INTDIR)\sbind.sbr" \
	"$(INTDIR)\search.sbr" \
	"$(INTDIR)\sort.sbr" \
	"$(INTDIR)\srchpref.sbr" \
	"$(INTDIR)\tmplout.sbr" \
	"$(INTDIR)\ufn.sbr" \
	"$(INTDIR)\unbind.sbr" \
	"$(INTDIR)\url.sbr" \
	"$(INTDIR)\wsockip.sbr"

"$(OUTDIR)\ldap32.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 oldnames.lib ldllcew.lib krbv4win.lib wshelper.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /map:"FULL" /debug /machine:IX86
# ADD LINK32 WSOCK32.LIB oldnames.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:IX86
# SUBTRACT LINK32 /map
LINK32_FLAGS=WSOCK32.LIB oldnames.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)/ldap32.pdb" /debug /machine:IX86\
 /def:".\ldap32.def" /out:"$(OUTDIR)/ldap32.dll" /implib:"$(OUTDIR)/ldap32.lib" 
DEF_FILE= \
	".\ldap32.def"
LINK32_OBJS= \
	"$(INTDIR)\abandon.obj" \
	"$(INTDIR)\add.obj" \
	"$(INTDIR)\addentry.obj" \
	"$(INTDIR)\bind.obj" \
	"$(INTDIR)\cache.obj" \
	"$(INTDIR)\charset.obj" \
	"$(INTDIR)\compare.obj" \
	"$(INTDIR)\decode.obj" \
	"$(INTDIR)\delete.obj" \
	"$(INTDIR)\disptmpl.obj" \
	"$(INTDIR)\dsparse.obj" \
	"$(INTDIR)\encode.obj" \
	"$(INTDIR)\error.obj" \
	"$(INTDIR)\free.obj" \
	"$(INTDIR)\friendly.obj" \
	"$(INTDIR)\getattr.obj" \
	"$(INTDIR)\getdn.obj" \
	"$(INTDIR)\getentry.obj" \
	"$(INTDIR)\getfilte.obj" \
	"$(INTDIR)\getvalue.obj" \
	"$(INTDIR)\io.obj" \
	"$(INTDIR)\kbind.obj" \
	"$(INTDIR)\kerberos.obj" \
	"$(INTDIR)\libldap.res" \
	"$(INTDIR)\modify.obj" \
	"$(INTDIR)\modrdn.obj" \
	"$(INTDIR)\msdos.obj" \
	"$(INTDIR)\open.obj" \
	"$(INTDIR)\regex.obj" \
	"$(INTDIR)\request.obj" \
	"$(INTDIR)\result.obj" \
	"$(INTDIR)\sbind.obj" \
	"$(INTDIR)\search.obj" \
	"$(INTDIR)\sort.obj" \
	"$(INTDIR)\srchpref.obj" \
	"$(INTDIR)\tmplout.obj" \
	"$(INTDIR)\ufn.obj" \
	"$(INTDIR)\unbind.obj" \
	"$(INTDIR)\url.obj" \
	"$(INTDIR)\wsockip.obj" \
	"..\..\..\..\MSDEV\LIB\WSOCK32.LIB"

"$(OUTDIR)\ldap32.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "libldap - Win32 Release"
# Name "libldap - Win32 Debug"

!IF  "$(CFG)" == "libldap - Win32 Release"

!ELSEIF  "$(CFG)" == "libldap - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\abandon.c
DEP_CPP_ABAND=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ABAND=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\abandon.obj" : $(SOURCE) $(DEP_CPP_ABAND) "$(INTDIR)"

"$(INTDIR)\abandon.sbr" : $(SOURCE) $(DEP_CPP_ABAND) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\add.c
DEP_CPP_ADD_C=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ADD_C=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\add.obj" : $(SOURCE) $(DEP_CPP_ADD_C) "$(INTDIR)"

"$(INTDIR)\add.sbr" : $(SOURCE) $(DEP_CPP_ADD_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\bind.c
DEP_CPP_BIND_=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_BIND_=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\externs.h"\
	".\macos.h"\
	

"$(INTDIR)\bind.obj" : $(SOURCE) $(DEP_CPP_BIND_) "$(INTDIR)"

"$(INTDIR)\bind.sbr" : $(SOURCE) $(DEP_CPP_BIND_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\cache.c
DEP_CPP_CACHE=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_CACHE=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\externs.h"\
	".\macos.h"\
	

"$(INTDIR)\cache.obj" : $(SOURCE) $(DEP_CPP_CACHE) "$(INTDIR)"

"$(INTDIR)\cache.sbr" : $(SOURCE) $(DEP_CPP_CACHE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\compare.c
DEP_CPP_COMPA=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_COMPA=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\compare.obj" : $(SOURCE) $(DEP_CPP_COMPA) "$(INTDIR)"

"$(INTDIR)\compare.sbr" : $(SOURCE) $(DEP_CPP_COMPA) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\delete.c
DEP_CPP_DELET=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_DELET=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\delete.obj" : $(SOURCE) $(DEP_CPP_DELET) "$(INTDIR)"

"$(INTDIR)\delete.sbr" : $(SOURCE) $(DEP_CPP_DELET) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\error.c
DEP_CPP_ERROR=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ERROR=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	

"$(INTDIR)\error.obj" : $(SOURCE) $(DEP_CPP_ERROR) "$(INTDIR)"

"$(INTDIR)\error.sbr" : $(SOURCE) $(DEP_CPP_ERROR) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\getfilte.c
DEP_CPP_GETFI=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\regex.h"\
	"..\..\include\sys/file.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_GETFI=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\getfilte.obj" : $(SOURCE) $(DEP_CPP_GETFI) "$(INTDIR)"

"$(INTDIR)\getfilte.sbr" : $(SOURCE) $(DEP_CPP_GETFI) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\regex.c
DEP_CPP_REGEX=\
	"..\..\include\portable.h"\
	"..\..\include\regex.h"\
	

"$(INTDIR)\regex.obj" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"

"$(INTDIR)\regex.sbr" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\modify.c
DEP_CPP_MODIF=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MODIF=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\modify.obj" : $(SOURCE) $(DEP_CPP_MODIF) "$(INTDIR)"

"$(INTDIR)\modify.sbr" : $(SOURCE) $(DEP_CPP_MODIF) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\modrdn.c
DEP_CPP_MODRD=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MODRD=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\modrdn.obj" : $(SOURCE) $(DEP_CPP_MODRD) "$(INTDIR)"

"$(INTDIR)\modrdn.sbr" : $(SOURCE) $(DEP_CPP_MODRD) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\getdn.c
DEP_CPP_GETDN=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_GETDN=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\getdn.obj" : $(SOURCE) $(DEP_CPP_GETDN) "$(INTDIR)"

"$(INTDIR)\getdn.sbr" : $(SOURCE) $(DEP_CPP_GETDN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\getentry.c
DEP_CPP_GETEN=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_GETEN=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\getentry.obj" : $(SOURCE) $(DEP_CPP_GETEN) "$(INTDIR)"

"$(INTDIR)\getentry.sbr" : $(SOURCE) $(DEP_CPP_GETEN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\getattr.c
DEP_CPP_GETAT=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_GETAT=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\getattr.obj" : $(SOURCE) $(DEP_CPP_GETAT) "$(INTDIR)"

"$(INTDIR)\getattr.sbr" : $(SOURCE) $(DEP_CPP_GETAT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\getvalue.c
DEP_CPP_GETVA=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_GETVA=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\getvalue.obj" : $(SOURCE) $(DEP_CPP_GETVA) "$(INTDIR)"

"$(INTDIR)\getvalue.sbr" : $(SOURCE) $(DEP_CPP_GETVA) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\addentry.c
DEP_CPP_ADDEN=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ADDEN=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\addentry.obj" : $(SOURCE) $(DEP_CPP_ADDEN) "$(INTDIR)"

"$(INTDIR)\addentry.sbr" : $(SOURCE) $(DEP_CPP_ADDEN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\result.c
DEP_CPP_RESUL=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\portable.h"\
	"..\..\include\sys/select.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_RESUL=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\externs.h"\
	".\macos.h"\
	".\ucx_select.h"\
	

"$(INTDIR)\result.obj" : $(SOURCE) $(DEP_CPP_RESUL) "$(INTDIR)"

"$(INTDIR)\result.sbr" : $(SOURCE) $(DEP_CPP_RESUL) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\search.c
DEP_CPP_SEARC=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_SEARC=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\search.obj" : $(SOURCE) $(DEP_CPP_SEARC) "$(INTDIR)"

"$(INTDIR)\search.sbr" : $(SOURCE) $(DEP_CPP_SEARC) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ufn.c
DEP_CPP_UFN_C=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_UFN_C=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\ufn.obj" : $(SOURCE) $(DEP_CPP_UFN_C) "$(INTDIR)"

"$(INTDIR)\ufn.sbr" : $(SOURCE) $(DEP_CPP_UFN_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\msdos.c
DEP_CPP_MSDOS=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	
NODEP_CPP_MSDOS=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	

"$(INTDIR)\msdos.obj" : $(SOURCE) $(DEP_CPP_MSDOS) "$(INTDIR)"

"$(INTDIR)\msdos.sbr" : $(SOURCE) $(DEP_CPP_MSDOS) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\sbind.c
DEP_CPP_SBIND=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_SBIND=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\sbind.obj" : $(SOURCE) $(DEP_CPP_SBIND) "$(INTDIR)"

"$(INTDIR)\sbind.sbr" : $(SOURCE) $(DEP_CPP_SBIND) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\unbind.c
DEP_CPP_UNBIN=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_UNBIN=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\externs.h"\
	".\macos.h"\
	

"$(INTDIR)\unbind.obj" : $(SOURCE) $(DEP_CPP_UNBIN) "$(INTDIR)"

"$(INTDIR)\unbind.sbr" : $(SOURCE) $(DEP_CPP_UNBIN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\kbind.c
DEP_CPP_KBIND=\
	"..\..\include\conf.h"\
	"..\..\include\des.h"\
	"..\..\include\krb.h"\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\lsh_pwd.h"\
	"..\..\include\mit_copy.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\conf-pc.h"\
	".\..\..\include\osconf.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_KBIND=\
	".\..\..\include\conf-bsd386i.h"\
	".\..\..\include\conf-bsdapollo.h"\
	".\..\..\include\conf-bsdibm032.h"\
	".\..\..\include\conf-bsdm68k.h"\
	".\..\..\include\conf-bsdsparc.h"\
	".\..\..\include\conf-bsdtahoe.h"\
	".\..\..\include\conf-bsdvax.h"\
	".\..\..\include\conf-pyr.h"\
	".\..\..\include\conf-ultmips2.h"\
	".\..\..\include\names.h"\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\kbind.obj" : $(SOURCE) $(DEP_CPP_KBIND) "$(INTDIR)"

"$(INTDIR)\kbind.sbr" : $(SOURCE) $(DEP_CPP_KBIND) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\friendly.c
DEP_CPP_FRIEN=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_FRIEN=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\friendly.obj" : $(SOURCE) $(DEP_CPP_FRIEN) "$(INTDIR)"

"$(INTDIR)\friendly.sbr" : $(SOURCE) $(DEP_CPP_FRIEN) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\disptmpl.c
DEP_CPP_DISPT=\
	"..\..\include\disptmpl.h"\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/file.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_DISPT=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\disptmpl.obj" : $(SOURCE) $(DEP_CPP_DISPT) "$(INTDIR)"

"$(INTDIR)\disptmpl.sbr" : $(SOURCE) $(DEP_CPP_DISPT) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\dsparse.c
DEP_CPP_DSPAR=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/file.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_DSPAR=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\dsparse.obj" : $(SOURCE) $(DEP_CPP_DSPAR) "$(INTDIR)"

"$(INTDIR)\dsparse.sbr" : $(SOURCE) $(DEP_CPP_DSPAR) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\free.c
DEP_CPP_FREE_=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_FREE_=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\free.obj" : $(SOURCE) $(DEP_CPP_FREE_) "$(INTDIR)"

"$(INTDIR)\free.sbr" : $(SOURCE) $(DEP_CPP_FREE_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\sort.c
DEP_CPP_SORT_=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	
NODEP_CPP_SORT_=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\sort.obj" : $(SOURCE) $(DEP_CPP_SORT_) "$(INTDIR)"

"$(INTDIR)\sort.sbr" : $(SOURCE) $(DEP_CPP_SORT_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\srchpref.c
DEP_CPP_SRCHP=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\srchpref.h"\
	"..\..\include\sys/file.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_SRCHP=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\srchpref.obj" : $(SOURCE) $(DEP_CPP_SRCHP) "$(INTDIR)"

"$(INTDIR)\srchpref.sbr" : $(SOURCE) $(DEP_CPP_SRCHP) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\tmplout.c
DEP_CPP_TMPLO=\
	"..\..\include\disptmpl.h"\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/file.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_TMPLO=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\tmplout.obj" : $(SOURCE) $(DEP_CPP_TMPLO) "$(INTDIR)"

"$(INTDIR)\tmplout.sbr" : $(SOURCE) $(DEP_CPP_TMPLO) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\libldap.rc

"$(INTDIR)\libldap.res" : $(SOURCE) "$(INTDIR)"
   $(RSC) $(RSC_PROJ) $(SOURCE)


# End Source File
################################################################################
# Begin Source File

SOURCE=.\request.c
DEP_CPP_REQUE=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\portable.h"\
	"..\..\include\sys/select.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_REQUE=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\externs.h"\
	".\macos.h"\
	".\ucx_select.h"\
	

"$(INTDIR)\request.obj" : $(SOURCE) $(DEP_CPP_REQUE) "$(INTDIR)"

"$(INTDIR)\request.sbr" : $(SOURCE) $(DEP_CPP_REQUE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\wsockip.c
DEP_CPP_WSOCK=\
	"..\..\include\_sys/filio.h"\
	"..\..\include\_sys/ioctl.h"\
	"..\..\include\arpa/nameser.h"\
	"..\..\include\hesiod.h"\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\netdb.h"\
	"..\..\include\netinet/in.h"\
	"..\..\include\portable.h"\
	"..\..\include\resolv.h"\
	"..\..\include\sys/filio.h"\
	"..\..\include\sys/ioctl.h"\
	"..\..\include\sys/select.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	"..\..\include\wshelper.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_WSOCK=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	

"$(INTDIR)\wsockip.obj" : $(SOURCE) $(DEP_CPP_WSOCK) "$(INTDIR)"

"$(INTDIR)\wsockip.sbr" : $(SOURCE) $(DEP_CPP_WSOCK) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\open.c
DEP_CPP_OPEN_=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\netinet/in.h"\
	"..\..\include\sys/param.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_OPEN_=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\open.obj" : $(SOURCE) $(DEP_CPP_OPEN_) "$(INTDIR)"

"$(INTDIR)\open.sbr" : $(SOURCE) $(DEP_CPP_OPEN_) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\ldap32.def

!IF  "$(CFG)" == "libldap - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "libldap - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=\MSDEV\LIB\WSOCK32.LIB

!IF  "$(CFG)" == "libldap - Win32 Release"

!ELSEIF  "$(CFG)" == "libldap - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\kerberos.c
DEP_CPP_KERBE=\
	"..\..\include\authlib.h"\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	
NODEP_CPP_KERBE=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	

"$(INTDIR)\kerberos.obj" : $(SOURCE) $(DEP_CPP_KERBE) "$(INTDIR)"

"$(INTDIR)\kerberos.sbr" : $(SOURCE) $(DEP_CPP_KERBE) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\url.c
DEP_CPP_URL_C=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_URL_C=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\url.obj" : $(SOURCE) $(DEP_CPP_URL_C) "$(INTDIR)"

"$(INTDIR)\url.sbr" : $(SOURCE) $(DEP_CPP_URL_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\charset.c
DEP_CPP_CHARS=\
	"..\..\include\lber.h"\
	"..\..\include\ldap.h"\
	"..\..\include\msdos.h"\
	"..\..\include\sys/param.h"\
	"..\..\include\sys/time.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	".\..\..\include\proto-ld.h"\
	".\ldap-int.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_CHARS=\
	".\..\..\include\proto-lber.h"\
	".\..\..\include\proto-ldap.h"\
	".\macos.h"\
	

"$(INTDIR)\charset.obj" : $(SOURCE) $(DEP_CPP_CHARS) "$(INTDIR)"

"$(INTDIR)\charset.sbr" : $(SOURCE) $(DEP_CPP_CHARS) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\liblber\io.c"
DEP_CPP_IO_C48=\
	"..\..\include\lber.h"\
	"..\..\include\msdos.h"\
	"..\..\include\netinet/in.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_IO_C48=\
	"..\liblber\macos.h"\
	".\..\..\include\proto-lber.h"\
	

BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\io.obj" : $(SOURCE) $(DEP_CPP_IO_C48) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\io.sbr" : $(SOURCE) $(DEP_CPP_IO_C48) "$(INTDIR)"
   $(BuildCmds)

# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\liblber\encode.c"
DEP_CPP_ENCOD=\
	"..\..\include\lber.h"\
	"..\..\include\msdos.h"\
	"..\..\include\netinet/in.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ENCOD=\
	"..\liblber\macos.h"\
	".\..\..\include\proto-lber.h"\
	

BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\encode.obj" : $(SOURCE) $(DEP_CPP_ENCOD) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\encode.sbr" : $(SOURCE) $(DEP_CPP_ENCOD) "$(INTDIR)"
   $(BuildCmds)

# End Source File
################################################################################
# Begin Source File

SOURCE="\src\ldap-3.3b1\libraries\liblber\decode.c"
DEP_CPP_DECOD=\
	"..\..\include\lber.h"\
	"..\..\include\msdos.h"\
	"..\..\include\netinet/in.h"\
	"..\..\include\sys\socket.h"\
	".\..\..\include\proto-lb.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_DECOD=\
	"..\liblber\macos.h"\
	".\..\..\include\proto-lber.h"\
	

BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\decode.obj" : $(SOURCE) $(DEP_CPP_DECOD) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\decode.sbr" : $(SOURCE) $(DEP_CPP_DECOD) "$(INTDIR)"
   $(BuildCmds)

# End Source File
# End Target
# End Project
################################################################################

# Microsoft Visual C++ generated build script - Do not modify

PROJ = LTEST
DEBUG = 1
PROGTYPE = 0
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = -d_DEBUG
R_RCDEFINES = -dNDEBUG
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = E:\SRC\LDAP-3.3B1\LIBRAR~1\MSDOS\WINSOCK\LTEST\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = CONSOLE.C   
FIRSTCPP =             
RC = rc
CFLAGS_D_WEXE = /nologo /G2 /W3 /Gf /Zi /AL /Od /D "_DEBUG" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /I "..\h" /I "..\winsock" /FR /GA /Fd"LIBLDAP.PDB"
CFLAGS_R_WEXE = /nologo /W3 /AM /O1 /D "NDEBUG" /D "DOS" /D "NEEDPROTOS" /D "WINSOCK" /I "..\winsock" /FR /GA 
LFLAGS_D_WEXE = /NOLOGO /NOD /PACKC:61440 /STACK:10240 /ALIGN:16 /ONERROR:NOEXE /CO  
LFLAGS_R_WEXE = /NOLOGO /NOD /PACKC:61440 /STACK:10240 /ALIGN:16 /ONERROR:NOEXE  
LIBS_D_WEXE = oldnames libw llibcew commdlg.lib olecli.lib olesvr.lib shell.lib 
LIBS_R_WEXE = oldnames libw mlibcew commdlg.lib olecli.lib olesvr.lib shell.lib 
RCFLAGS = /nologo
RESFLAGS = /nologo
RUNFLAGS = 
DEFFILE = LTEST.DEF
OBJS_EXT = 
LIBS_EXT = ..\..\..\LIBLDAP\LIBLDAP.LIB ..\..\..\LIBLDAP\WINSOCK.LIB 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WEXE)
LFLAGS = $(LFLAGS_D_WEXE)
LIBS = $(LIBS_D_WEXE)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WEXE)
LFLAGS = $(LFLAGS_R_WEXE)
LIBS = $(LIBS_R_WEXE)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = CONSOLE.SBR \
		TEXTWIND.SBR \
		GETOPT.SBR \
		TEST.SBR


LIBLDAP_DEP = 

WINSOCK_DEP = 

CONSOLE_DEP = c:\msvc\include\winsock.h \
	e:\src\ldap-3.3b1\librar~1\msdos\winsock\ltest\console.h


TEXTWIND_DEP = e:\src\ldap-3.3b1\librar~1\msdos\winsock\ltest\console.h \
	e:\src\ldap-3.3b1\librar~1\msdos\winsock\ltest\textwind.h


LTEST_RCDEP = e:\src\ldap-3.3b1\librar~1\msdos\winsock\ltest\console.h \
	e:\src\ldap-3.3b1\librar~1\msdos\winsock\ltest\inpdlg.dlg


GETOPT_DEP = e:\src\ldap-3.3b1\include\lber.h \
	e:\src\ldap-3.3b1\include\proto-lb.h


TEST_DEP = e:\src\ldap-3.3b1\include\msdos.h \
	c:\msvc\include\winsock.h \
	e:\src\ldap-3.3b1\include\sys/socket.h \
	e:\src\ldap-3.3b1\include\sys/file.h \
	e:\src\ldap-3.3b1\include\lber.h \
	e:\src\ldap-3.3b1\include\proto-lb.h \
	e:\src\ldap-3.3b1\include\ldap.h \
	e:\src\ldap-3.3b1\include\proto-ld.h


all:	$(PROJ).EXE $(PROJ).BSC

CONSOLE.OBJ:	CONSOLE.C $(CONSOLE_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c CONSOLE.C

TEXTWIND.OBJ:	TEXTWIND.C $(TEXTWIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c TEXTWIND.C

LTEST.RES:	LTEST.RC $(LTEST_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r LTEST.RC

GETOPT.OBJ:	..\..\..\MACINTOS\GETOPT.C $(GETOPT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\..\..\MACINTOS\GETOPT.C

TEST.OBJ:	..\..\..\LIBLDAP\TEST.C $(TEST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\..\..\LIBLDAP\TEST.C


$(PROJ).EXE::	LTEST.RES

$(PROJ).EXE::	CONSOLE.OBJ TEXTWIND.OBJ GETOPT.OBJ TEST.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
CONSOLE.OBJ +
TEXTWIND.OBJ +
GETOPT.OBJ +
TEST.OBJ +
$(OBJS_EXT)
$(PROJ).EXE
$(MAPFILE)
c:\msvc\lib\+
c:\msvc\mfc\lib\+
c:\src\lib\+
e:.\+
..\..\..\LIBLDAP\LIBLDAP.LIB+
..\..\..\LIBLDAP\WINSOCK.LIB+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) LTEST.RES $@
	@copy $(PROJ).CRF MSVC.BND

$(PROJ).EXE::	LTEST.RES
	if not exist MSVC.BND 	$(RC) $(RESFLAGS) LTEST.RES $@

run: $(PROJ).EXE
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<

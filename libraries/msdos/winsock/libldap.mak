# Microsoft Visual C++ generated build script - Do not modify

PROJ = LIBLDAP
DEBUG = 0
PROGTYPE = 1
CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = /d_DEBUG 
R_RCDEFINES = /dNDEBUG 
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = C:\SRC\LDAP\LIBRAR~1\LIBLDAP\
USEMFC = 0
CC = cl
CPP = cl
CXX = cl
CCREATEPCHFLAG = 
CPPCREATEPCHFLAG = 
CUSEPCHFLAG = 
CPPUSEPCHFLAG = 
FIRSTC = ABANDON.C   
FIRSTCPP =             
RC = rc
CFLAGS_D_WDLL = /nologo /G2 /W3 /Gf /Zi /ALu /Od /D "_DEBUG" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "KERBEROS" /FR /Fd"LIBLDAP.PDB"
CFLAGS_R_WDLL = /nologo /f- /G3 /W3 /Gf /ALu /Od /D "NDEBUG" /D "WINSOCK" /D "DOS" /D "NEEDPROTOS" /D "NO_USERINTERFACE" /D "KERBEROS" 
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /CO /MAP:FULL
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /MAP:FULL
LIBS_D_WDLL = oldnames libw ldllcew krbv4win commdlg.lib olecli.lib olesvr.lib shell.lib 
LIBS_R_WDLL = oldnames libw ldllcew krbv4win commdlg.lib olecli.lib olesvr.lib shell.lib 
RCFLAGS = /nologo 
RESFLAGS = /nologo 
RUNFLAGS = 
DEFFILE = LIBLDAP.DEF
OBJS_EXT = 
LIBS_EXT = WINSOCK.LIB 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WDLL)
LFLAGS = $(LFLAGS_D_WDLL)
LIBS = $(LIBS_D_WDLL)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WDLL)
LFLAGS = $(LFLAGS_R_WDLL)
LIBS = $(LIBS_R_WDLL)
MAPFILE = nul
RCDEFINES = $(R_RCDEFINES)
!endif
!if [if exist MSVC.BND del MSVC.BND]
!endif
SBRS = ABANDON.SBR \
		ADD.SBR \
		BIND.SBR \
		CACHE.SBR \
		COMPARE.SBR \
		DELETE.SBR \
		ERROR.SBR \
		GETFILTE.SBR \
		REGEX.SBR \
		MODIFY.SBR \
		MODRDN.SBR \
		GETDN.SBR \
		GETENTRY.SBR \
		GETATTR.SBR \
		GETVALUE.SBR \
		ADDENTRY.SBR \
		RESULT.SBR \
		SEARCH.SBR \
		UFN.SBR \
		DECODE.SBR \
		ENCODE.SBR \
		IO.SBR \
		MSDOS.SBR \
		SBIND.SBR \
		UNBIND.SBR \
		KBIND.SBR \
		FRIENDLY.SBR \
		DISPTMPL.SBR \
		DSPARSE.SBR \
		FREE.SBR \
		SORT.SBR \
		SRCHPREF.SBR \
		TMPLOUT.SBR \
		REQUEST.SBR \
		WSOCKIP.SBR \
		OPEN.SBR \
		CHARSET.SBR \
		URL.SBR


WINSOCK_DEP = 

ABANDON_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


ADD_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


BIND_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


CACHE_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


COMPARE_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


DELETE_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


ERROR_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


GETFILTE_DEP = c:\src\ldap\include\regex.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/file.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


REGEX_DEP = c:\src\ldap\include\portable.h \
	c:\src\ldap\include\regex.h


MODIFY_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


MODRDN_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


GETDN_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


GETENTRY_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


GETATTR_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


GETVALUE_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


ADDENTRY_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


RESULT_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\sys/select.h \
	c:\src\ldap\include\portable.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


SEARCH_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


UFN_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


DECODE_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\netinet/in.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h


ENCODE_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\netinet/in.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h


IO_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\netinet/in.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h


MSDOS_DEP = c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\proto-ld.h


SBIND_DEP = c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


UNBIND_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


KBIND_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\krb.h \
	c:\src\ldap\include\mit_copy.h \
	c:\src\ldap\include\conf.h \
	c:\src\ldap\include\osconf.h \
	c:\src\ldap\include\conf-pc.h \
	c:\src\ldap\include\des.h \
	c:\src\ldap\include\lsh_pwd.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


FRIENDLY_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


DISPTMPL_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/file.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\include\disptmpl.h


DSPARSE_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/file.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


FREE_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


SORT_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h


SRCHPREF_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/file.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\include\srchpref.h


TMPLOUT_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/file.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\include\disptmpl.h


LIBLDAP_RCDEP = 

REQUEST_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\sys/select.h \
	c:\src\ldap\include\portable.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


WSOCKIP_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\wshelper.h \
	c:\src\ldap\include\resolv.h \
	c:\src\ldap\include\arpa/nameser.h \
	c:\src\ldap\include\hesiod.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\netinet/in.h \
	c:\src\ldap\include\netdb.h \
	c:\src\ldap\include\sys\socket.h \
	c:\src\ldap\include\sys/select.h \
	c:\src\ldap\include\portable.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\include\_sys/filio.h \
	c:\src\ldap\include\sys/filio.h \
	c:\src\ldap\include\_sys/ioctl.h \
	c:\src\ldap\include\sys/ioctl.h


OPEN_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\sys/param.h \
	c:\src\ldap\include\netinet/in.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


CHARSET_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\sys/param.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


URL_DEP = c:\src\ldap\include\msdos.h \
	c:\msvc\include\winsock.h \
	c:\src\ldap\include\sys/socket.h \
	c:\src\ldap\include\lber.h \
	c:\src\ldap\include\proto-lb.h \
	c:\src\ldap\include\ldap.h \
	c:\src\ldap\include\proto-ld.h \
	c:\src\ldap\librar~1\libldap\ldap-int.h


all:	$(PROJ).DLL

ABANDON.OBJ:	ABANDON.C $(ABANDON_DEP)
	$(CC) $(CFLAGS) $(CCREATEPCHFLAG) /c ABANDON.C

ADD.OBJ:	ADD.C $(ADD_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ADD.C

BIND.OBJ:	BIND.C $(BIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c BIND.C

CACHE.OBJ:	CACHE.C $(CACHE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CACHE.C

COMPARE.OBJ:	COMPARE.C $(COMPARE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c COMPARE.C

DELETE.OBJ:	DELETE.C $(DELETE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c DELETE.C

ERROR.OBJ:	ERROR.C $(ERROR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ERROR.C

GETFILTE.OBJ:	GETFILTE.C $(GETFILTE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETFILTE.C

REGEX.OBJ:	REGEX.C $(REGEX_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c REGEX.C

MODIFY.OBJ:	MODIFY.C $(MODIFY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c MODIFY.C

MODRDN.OBJ:	MODRDN.C $(MODRDN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c MODRDN.C

GETDN.OBJ:	GETDN.C $(GETDN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETDN.C

GETENTRY.OBJ:	GETENTRY.C $(GETENTRY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETENTRY.C

GETATTR.OBJ:	GETATTR.C $(GETATTR_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETATTR.C

GETVALUE.OBJ:	GETVALUE.C $(GETVALUE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETVALUE.C

ADDENTRY.OBJ:	ADDENTRY.C $(ADDENTRY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ADDENTRY.C

RESULT.OBJ:	RESULT.C $(RESULT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RESULT.C

SEARCH.OBJ:	SEARCH.C $(SEARCH_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c SEARCH.C

UFN.OBJ:	UFN.C $(UFN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c UFN.C

DECODE.OBJ:	..\LIBLBER\DECODE.C $(DECODE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBLBER\DECODE.C

ENCODE.OBJ:	..\LIBLBER\ENCODE.C $(ENCODE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBLBER\ENCODE.C

IO.OBJ:	..\LIBLBER\IO.C $(IO_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\LIBLBER\IO.C

MSDOS.OBJ:	MSDOS.C $(MSDOS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c MSDOS.C

SBIND.OBJ:	SBIND.C $(SBIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c SBIND.C

UNBIND.OBJ:	UNBIND.C $(UNBIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c UNBIND.C

KBIND.OBJ:	KBIND.C $(KBIND_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c KBIND.C

FRIENDLY.OBJ:	FRIENDLY.C $(FRIENDLY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c FRIENDLY.C

DISPTMPL.OBJ:	DISPTMPL.C $(DISPTMPL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c DISPTMPL.C

DSPARSE.OBJ:	DSPARSE.C $(DSPARSE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c DSPARSE.C

FREE.OBJ:	FREE.C $(FREE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c FREE.C

SORT.OBJ:	SORT.C $(SORT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c SORT.C

SRCHPREF.OBJ:	SRCHPREF.C $(SRCHPREF_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c SRCHPREF.C

TMPLOUT.OBJ:	TMPLOUT.C $(TMPLOUT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c TMPLOUT.C

LIBLDAP.RES:	LIBLDAP.RC $(LIBLDAP_RCDEP)
	$(RC) $(RCFLAGS) $(RCDEFINES) -r LIBLDAP.RC

REQUEST.OBJ:	REQUEST.C $(REQUEST_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c REQUEST.C

WSOCKIP.OBJ:	WSOCKIP.C $(WSOCKIP_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c WSOCKIP.C

OPEN.OBJ:	OPEN.C $(OPEN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c OPEN.C

CHARSET.OBJ:	CHARSET.C $(CHARSET_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c CHARSET.C

URL.OBJ:	URL.C $(URL_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c URL.C


$(PROJ).DLL::	LIBLDAP.RES

$(PROJ).DLL::	ABANDON.OBJ ADD.OBJ BIND.OBJ CACHE.OBJ COMPARE.OBJ DELETE.OBJ ERROR.OBJ \
	GETFILTE.OBJ REGEX.OBJ MODIFY.OBJ MODRDN.OBJ GETDN.OBJ GETENTRY.OBJ GETATTR.OBJ GETVALUE.OBJ \
	ADDENTRY.OBJ RESULT.OBJ SEARCH.OBJ UFN.OBJ DECODE.OBJ ENCODE.OBJ IO.OBJ MSDOS.OBJ \
	SBIND.OBJ UNBIND.OBJ KBIND.OBJ FRIENDLY.OBJ DISPTMPL.OBJ DSPARSE.OBJ FREE.OBJ SORT.OBJ \
	SRCHPREF.OBJ TMPLOUT.OBJ REQUEST.OBJ WSOCKIP.OBJ OPEN.OBJ CHARSET.OBJ URL.OBJ $(OBJS_EXT) $(DEFFILE)
	echo >NUL @<<$(PROJ).CRF
ABANDON.OBJ +
ADD.OBJ +
BIND.OBJ +
CACHE.OBJ +
COMPARE.OBJ +
DELETE.OBJ +
ERROR.OBJ +
GETFILTE.OBJ +
REGEX.OBJ +
MODIFY.OBJ +
MODRDN.OBJ +
GETDN.OBJ +
GETENTRY.OBJ +
GETATTR.OBJ +
GETVALUE.OBJ +
ADDENTRY.OBJ +
RESULT.OBJ +
SEARCH.OBJ +
UFN.OBJ +
DECODE.OBJ +
ENCODE.OBJ +
IO.OBJ +
MSDOS.OBJ +
SBIND.OBJ +
UNBIND.OBJ +
KBIND.OBJ +
FRIENDLY.OBJ +
DISPTMPL.OBJ +
DSPARSE.OBJ +
FREE.OBJ +
SORT.OBJ +
SRCHPREF.OBJ +
TMPLOUT.OBJ +
REQUEST.OBJ +
WSOCKIP.OBJ +
OPEN.OBJ +
CHARSET.OBJ +
URL.OBJ +
$(OBJS_EXT)
$(PROJ).DLL
$(MAPFILE)
c:\msvc\lib\+
c:\msvc\mfc\lib\+
c:\src\lib\+
WINSOCK.LIB+
$(LIBS)
$(DEFFILE);
<<
	link $(LFLAGS) @$(PROJ).CRF
	$(RC) $(RESFLAGS) LIBLDAP.RES $@
	@copy $(PROJ).CRF MSVC.BND
	implib /nowep $(PROJ).LIB $(PROJ).DLL

$(PROJ).DLL::	LIBLDAP.RES
	if not exist MSVC.BND 	$(RC) $(RESFLAGS) LIBLDAP.RES $@

run: $(PROJ).DLL
	$(PROJ) $(RUNFLAGS)


$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<

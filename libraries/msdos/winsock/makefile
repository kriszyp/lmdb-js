# Microsoft Visual C++ generated build script - Do not modify
# Microsoft Visual C++ generated build script - Do not modify
# but due to buffer length limitataions for both preprocessor defines
# and include paths we went to using this file as an external makefile
# April 1995 sgr@umich.edu

PROJ = LIBLDAP
DEBUG = 0
PROGTYPE = 1

WINSOCK = 1	# want winsock api, no vendor specific calls
DOS = 1		# windows lives on top of DOS at present
NEEDPROTOS = 1	# need strict typeing in fcn declarations
KERBEROS = 1	# Kerberos or no, your choice

#include paths will vary per site,  I've broken them up by function
INC_MSVC = c:\msvc\include
INC_LDAP = q:\src\ldap-3.2b1\include
INC_KERBEROS = q:\src\krb\mit_env\kerberos\include;q:\src\krb\mit_env\kerberos
INC_WSHELPER = c:\src\mit\wshelper
INC_AUTHMAN = c:\src\authman\dll
INC_MITENV = q:\src\krb\mit_env\localh

#order is important
INCLUDE = $(INC_MSVC);$(INC_LDAP);$(INC_AUTHMAN);$(INC_MITENV);$(INC_KERBEROS);$(INC_WSHELPER)

LDAP_FLAGS = /D "TEMPLATEFILE" ="""ldtmpl.cfg"""\
	/D "FILTERFILE"="""ldfilter.cfg"""

!if "$(KERBEROS)" == "1"
# WSHELPER
# with kerberos, we need to use WSHELPER (Winsock Helper)  to do 
# gethostbyaddr() calls for us because we can't count on the vendor's 
# (Novell) tcp/ip stack doing this right.  The real name of the ldap 
# server is required to get service tickets.
#
LDAP_FLAGS = $(LDAP_FLAGS) /D "KERBEROS" /D "WSHELPER" /D "AUTHMAN"
#	SET INCLUDE=$(INCLUDE), $(INC_KERBEROS), $(INC_WSHELPER), $(INC_AUTHMAN), $(INC_MITENV)
!endif
# _WINDOWS
# authman.h requires _WINDOWS (with a value!), which is set automatically by
# particular options related to prolog/epilog code generation 
# which are true for AUTHMAN, but not libldap, so do this manually.
#
#
# __MSDOS__
# krb.h (well really osconf.h, via conf.h, via krb.h) doesn't recognize
# microsoft's default "_MSDOS".  It wants __MSDOS__, so provide it.
#
# WINDOWS
# same crap, this time from conf-pc.h, this time with WINDOWS
#	
# _WINDLL
# Wshelper.h requires _WINDLL to be defined.  Default configuration
# of libldap doesn't use any prolog/epilog optimization, so _WINDLL
# isn't defined by default.
#
!if "$(WINSOCK)"=="1"
LDAP_FLAGS = $(LDAP_FLAGS)\
		/D "WINSOCK"\
		/D "_WINDOWS"\
		/D "__MSDOS__"\
		/D "WINDOWS"\
		/D "_WINDLL"\
		/D "NO_USERINTERFACE"
!endif
!if "$(DOS)"=="1"
LDAP_FLAGS = $(LDAP_FLAGS) /D "DOS"
!endif
!if "$(NEEDPROTOS)"=="1"
LDAP_FLAGS = $(LDAP_FLAGS) /D "NEEDPROTOS"
!endif

CALLER = 
ARGS = 
DLLS = 
D_RCDEFINES = /d_DEBUG 
R_RCDEFINES = /dNDEBUG 
ORIGIN = MSVC
ORIGIN_VER = 1.00
PROJPATH = Q:\SRC\LDAP-3.2B1\LIB\LIBLDAP\
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
CFLAGS_D_WDLL = /nologo /G2 /W3 /Gf /Zi /ALu /Od /D "_DEBUG" /FR /Fd"LIBLDAP.PDB"
CFLAGS_R_WDLL = /nologo /f- /G3 /W3 /Gf /ALu /Od /D "NDEBUG" /FR
LFLAGS_D_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /CO /MAP:FULL
LFLAGS_R_WDLL = /NOLOGO /NOD /NOE /PACKC:61440 /ALIGN:16 /ONERROR:NOEXE /MAP:FULL
LIBS_D_WDLL = oldnames libw ldllcew authlib krbv4win wshelper commdlg.lib olecli.lib olesvr.lib shell.lib 
LIBS_R_WDLL = oldnames libw ldllcew authlib krbv4win wshelper commdlg.lib olecli.lib olesvr.lib shell.lib 
RCFLAGS = /nologo 
RESFLAGS = /nologo 
RUNFLAGS = 
DEFFILE = LIBLDAP.DEF
OBJS_EXT = 
LIBS_EXT = WINSOCK.LIB 
!if "$(DEBUG)" == "1"
CFLAGS = $(CFLAGS_D_WDLL) $(LDAP_FLAGS)
LFLAGS = $(LFLAGS_D_WDLL)
LIBS = $(LIBS_D_WDLL)
MAPFILE = nul
RCDEFINES = $(D_RCDEFINES)
!else
CFLAGS = $(CFLAGS_R_WDLL) $(LDAP_FLAGS)
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
		ADDENTRY.SBR \
		RESULT.SBR \
		SEARCH.SBR \
		UFN.SBR \
		OPENWSA.SBR \
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
		KERBEROS.SBR \
		GETVALUE.SBR


WINSOCK_DEP = 

ABANDON_DEP = $(INC_LDAP)\sys\socket.h \
	$(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


ADD_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


BIND_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


CACHE_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


COMPARE_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h


DELETE_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


ERROR_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


GETFILTE_DEP = $(INC_LDAP)\regex.h \
	$(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/file.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


REGEX_DEP = $(INC_LDAP)\portable.h \
	$(INC_LDAP)\regex.h


MODIFY_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h


MODRDN_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h


GETDN_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


GETENTRY_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


GETATTR_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


ADDENTRY_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


RESULT_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\sys/select.h \
	$(INC_LDAP)\portable.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


SEARCH_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\msdos.h


UFN_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


OPENWSA_DEP = $(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\msdos.h \
	q:\src\mit\localh\wshelper.h \
	q:\src\mit\localh\resolv.h \
	q:\src\mit\localh\arpa/nameser.h \
	q:\src\mit\localh\hesiod.h


DECODE_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\netinet/in.h \
	$(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h


ENCODE_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\netinet/in.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h


IO_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\netinet/in.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\msdos.h


MSDOS_DEP = $(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\msdos.h


SBIND_DEP = $(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h


UNBIND_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


KBIND_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	c:\src\h\krbv4\krb.h \
	q:\src\mit\localh\mit_copy.h \
	q:\src\mit\localh\conf.h \
	q:\src\mit\localh\osconf.h \
	q:\src\mit\localh\conf-pc.h \
	c:\src\h\krbv4\des.h \
	q:\src\mit\localh\lsh_pwd.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


FRIENDLY_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


DISPTMPL_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/file.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\disptmpl.h


DSPARSE_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/file.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


FREE_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


SORT_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


SRCHPREF_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/file.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\srchpref.h


TMPLOUT_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/file.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\disptmpl.h


LIBLDAP_RCDEP = 

KERBEROS_DEP = $(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\proto-ld.h \
	$(INC_LDAP)\msdos.h \
	c:\src\authman\dll\authlib.h


GETVALUE_DEP = $(INC_LDAP)\msdos.h \
	$(INC_LDAP)\winsock.h \
	$(INC_LDAP)\sys/socket.h \
	$(INC_LDAP)\lber.h \
	$(INC_LDAP)\proto-lb.h \
	$(INC_LDAP)\ldap.h \
	$(INC_LDAP)\proto-ld.h


all:	$(PROJ).DLL $(PROJ).BSC

clean:
	del *.aps
	del *.bsc 
	del *.pdb 
	del *.vcw 
	del *.res
	del *.pch
	del *.obj
	del *.sbr
#	del *.map

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

ADDENTRY.OBJ:	ADDENTRY.C $(ADDENTRY_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ADDENTRY.C

RESULT.OBJ:	RESULT.C $(RESULT_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c RESULT.C

SEARCH.OBJ:	SEARCH.C $(SEARCH_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c SEARCH.C

UFN.OBJ:	UFN.C $(UFN_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c UFN.C

OPENWSA.OBJ:	OPENWSA.C $(OPENWSA_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c OPENWSA.C

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

KERBEROS.OBJ:	..\MSDOS\KERBEROS.C $(KERBEROS_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c ..\MSDOS\KERBEROS.C

GETVALUE.OBJ:	GETVALUE.C $(GETVALUE_DEP)
	$(CC) $(CFLAGS) $(CUSEPCHFLAG) /c GETVALUE.C


$(PROJ).DLL::	LIBLDAP.RES

$(PROJ).DLL::	ABANDON.OBJ ADD.OBJ BIND.OBJ CACHE.OBJ COMPARE.OBJ DELETE.OBJ ERROR.OBJ \
	GETFILTE.OBJ REGEX.OBJ MODIFY.OBJ MODRDN.OBJ GETDN.OBJ GETENTRY.OBJ GETATTR.OBJ ADDENTRY.OBJ \
	RESULT.OBJ SEARCH.OBJ UFN.OBJ OPENWSA.OBJ DECODE.OBJ ENCODE.OBJ IO.OBJ MSDOS.OBJ \
	SBIND.OBJ UNBIND.OBJ KBIND.OBJ FRIENDLY.OBJ DISPTMPL.OBJ DSPARSE.OBJ FREE.OBJ SORT.OBJ \
	SRCHPREF.OBJ TMPLOUT.OBJ KERBEROS.OBJ GETVALUE.OBJ $(OBJS_EXT) $(DEFFILE)
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
ADDENTRY.OBJ +
RESULT.OBJ +
SEARCH.OBJ +
UFN.OBJ +
OPENWSA.OBJ +
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
KERBEROS.OBJ +
GETVALUE.OBJ +
$(OBJS_EXT)
$(PROJ).DLL
$(MAPFILE)
c:\msvc\lib\+
c:\msvc\mfc\lib\+
c:\src\lib\+
c:\src\mit\locallib\+
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

#clean:
#	del *.aps
#	del *.bsc 
#	del *.pdb 
#	del *.vcw 
#	del *.res
#	del *.pch
#	del *.obj
#	del *.sbr
#	del *.map

$(PROJ).BSC: $(SBRS)
	bscmake @<<
/o$@ $(SBRS)
<<


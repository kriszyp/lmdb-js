#
# makefile.nmake stub makefile for nmake
# 15 Dec 1995 : sgr
#
#<target> :[:] <dependent> [... <dependent>]
#	<commands>
#	[<commands>]
#
# $@	Current target's full name (path, base, extension)
# $$@	Current target's full name (path, base, extension)
#	(Valid only as a dependent in a dependency.)
# $*	Current target's path & base name minus extension
# $**	All dependents of the current target.
# $?	All dependents with a later timestamp than the current target.
# $<	Dependent file with a later timestamp that the current target.
#	(Valid only in commands in inference rules.)
#
# Modifiers $(@F)
# B	Base name
# F	Base name + extension (Full name)
# D	Drive + directory
# R	Drive + directory + base name (Reusable name)

ROOT = ..\..\..\..
HELP = $(ROOT)\windows\help
LDAP = $(ROOT)\librar~1\libldap
LTEST = $(ROOT)\librar~1\msdos\winsock\ltest
WINSOCK = $(ROOT)\librar~1\msdos\winsock
MAININC = $(ROOT)\include
LINCL = incKit
BIN = binaries
BINARIES = \
		$(BIN)\debug\libldap.dll \
		$(BIN)\debug\libldap.lib \
		$(BIN)\release\libldap.dll \
		$(BIN)\release\libldap.lib \
		$(BIN)\debug\ltest.exe \
		$(BIN)\debug\ldap32.dll \
		$(BIN)\debug\ldap32.lib \
		$(BIN)\release\ldap32.dll \
		$(BIN)\release\ldap32.lib \
		$(BIN)\debug\ltest32.exe \
		libldap.hlp \
		ldap32.hlp

all: WinLdap.zip

WinLdap.zip : 	\
		$(BINARIES) \
# Using Wax500 as a test case, only the
# following include files are needed to make
# a non-kerberized ldap32.dll
# or a kerberized libldap.dll
		$(LINCL)\disptmpl.h \
		$(LINCL)\lber.h \
		$(LINCL)\ldap.h \
		$(LINCL)\msdos.h \
		$(LINCL)\proto-ld.h \
		$(LINCL)\proto-lb.h \
		$(LINCL)\srchpref.h \
		srchpref.cfg \
		disptmpl.cfg \
		ldfriend.cfg \
		ldfilter.cfg \
		readme.txt
	-!pkzip -P -u $@ $?
	del *.cfg

$(BIN)\debug\libldap.dll : $(LDAP)\debug\libldap.dll 
	-@md $(@D)
	-copy $? $@

$(BIN)\debug\libldap.lib : $(LDAP)\debug\libldap.lib 
	-@md $(@D)
	-copy $? $@

$(BIN)\debug\ltest.exe : $(LTEST)\ltest.exe 
	-@md $(@D)
	-copy $? $@

$(BIN)\debug\ldap32.dll : $(LDAP)\debug\ldap32.dll 
	-@md $(@D)
	-copy $? $@

$(BIN)\debug\ldap32.lib : $(LDAP)\debug\ldap32.lib 
	-@md $(@D)
	-copy $? $@

$(BIN)\debug\ltest32.exe : $(LTEST)\debug\ltest32.exe 
	-@md $(@D)
	-copy $? $@

$(BIN)\release\libldap.dll : $(LDAP)\release\libldap.dll 
	-@md $(@D)
	-copy $? $@

$(BIN)\release\libldap.lib : $(LDAP)\release\libldap.lib 
	-@md $(@D)
	-copy $? $@

$(BIN)\release\ldap32.dll : $(LDAP)\release\ldap32.dll 
	-@md $(@D)
	-copy $? $@

$(BIN)\release\ldap32.lib : $(LDAP)\release\ldap32.lib 
	-@md $(@D)
	-copy $? $@

$(LINCL)\disptmpl.h : $(MAININC)\disptmpl.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\lber.h : $(MAININC)\lber.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\ldap.h : $(MAININC)\ldap.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\msdos.h : $(MAININC)\msdos.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\proto-ld.h : $(MAININC)\proto-ld.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\proto-lb.h : $(MAININC)\proto-lb.h
	-@md $(@D)
	-copy $? $@

$(LINCL)\srchpref.h : $(MAININC)\srchpref.h
	-@md $(@D)
	-copy $? $@

libldap.hlp : $(HELP)\build\libldap.hlp
	-copy $? $@

ldap32.hlp  : $(HELP)\ldap32.hlp
	-copy $? $@

srchpref.cfg : 	$(LDAP)\ldapsearchprefs.conf
	-copy $** $@ 

ldfilter.cfg : 	$(LDAP)\ldapfilter.conf
	-copy $** $@ 

disptmpl.cfg : 	$(LDAP)\ldaptemplates.conf
	-copy $** $@ 

ldfriend.cfg : 	$(LDAP)\ldapfriendly
	-copy $** $@ 


$(LDAP)\debug\libldap.dll :
$(LDAP)\debug\libldap.lib :
$(LDAP)\release\libldap.dll :
$(LDAP)\release\libldap.lib :
$(LTEST)\ltest.exe :
$(LDAP)\debug\ldap32.dll :
$(LDAP)\debug\ldap32.lib :
$(LDAP)\release\ldap32.dll :
$(LDAP)\release\ldap32.lib :
$(LTEST)\debug\ltest32.exe :
$(HELP)\build\libldap.hlp :
$(HELP)\ldap32.hlp :
$(LDAP)\ldapsearchprefs.conf :
$(LDAP)\ldapfilter.conf :
$(LDAP)\ldaptemplates.conf :
$(LDAP)\ldapfriendly :
readme.txt :

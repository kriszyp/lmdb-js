@rem
@rem this is UNsetupwsa.bat  It reverses what setupwsa.bat does.
@rem you SHOULD NOT use this file !!!
@rem MSDOS batch file to setup LDAP source area for Windows Socket API build
@rem This should be run from the ***ROOT*** of the LDAP source tree
@rem
@rem Updated 1 December 1995 * Steve Rothwell * University of Michigan
@rem

@echo "You SHOULD NOT USE unsetupwsa.bat"
@goto END

:UNSETUP

rem  original set of empty files
call copyback libraries\msdos\winsock\include\file.h include\sys\file.h 
call copyback libraries\msdos\winsock\include\select.h include\sys\select.h 
call copyback libraries\msdos\winsock\include\socket.h include\sys\socket.h 
call copyback libraries\msdos\winsock\include\param.h include\sys\param.h 
call copyback libraries\msdos\winsock\include\ioctl.h include\sys\ioctl.h 
call copyback libraries\msdos\winsock\include\filio.h include\sys\filio.h 
call copyback libraries\msdos\winsock\include\time.h include\sys\time.h 
call copyback libraries\msdos\winsock\include\in.h include\netinet\in.h 

rem  a newer copy
call copyback libraries\msdos\winsock\include\wsa\winsock.h include\winsock.h 

rem  from MIT's kerberos stuff
call copyback libraries\msdos\winsock\include\krb\krb.h include\krb.h 
call copyback libraries\msdos\winsock\include\krb\des.h include\des.h 

rem  from MIT's "localh" collection
call copyback libraries\msdos\winsock\include\krb\mit\mit_copy.h include\mit_copy.h 
call copyback libraries\msdos\winsock\include\krb\mit\conf.h include\conf.h 
call copyback libraries\msdos\winsock\include\krb\mit\conf-pc.h include\conf-pc.h 
call copyback libraries\msdos\winsock\include\krb\mit\osconf.h include\osconf.h 
call copyback libraries\msdos\winsock\include\krb\mit\lsh_pwd.h include\lsh_pwd.h 
call copyback libraries\msdos\winsock\include\krb\mit\wshelper.h include\wshelper.h 
call copyback libraries\msdos\winsock\include\krb\mit\resolv.h include\resolv.h 
call copyback libraries\msdos\winsock\include\krb\mit\hesiod.h include\hesiod.h 
call copyback libraries\msdos\winsock\include\krb\mit\arpa\nameser.h include\arpa\nameser.h 

rem  from Novell's LWP "toolkit" collection
call copyback libraries\msdos\winsock\include\net\_sys\filio.h include\_sys\filio.h 
call copyback libraries\msdos\winsock\include\net\_sys\ioctl.h include\_sys\ioctl.h 
call copyback libraries\msdos\winsock\include\net\netdb.h include\netdb.h 

call copyback libraries\msdos\winsock\include\wsa.h include\msdos.h
call copyback libraries\msdos\winsock\wsa.c libraries\libldap\msdos.c

call copyback libraries\msdos\winsock\wsockip.c libraries\libldap\wsockip.c 
call copyback libraries\msdos\winsock\kerberos.c libraries\libldap\kerberos.c 

rem  the Pieces you need for MSVC 1.52c
call copyback libraries\msdos\winsock\libldap.def libraries\libldap\libldap.def 
call copyback libraries\msdos\winsock\libldap.mak libraries\libldap\libldap.mak 
call copyback libraries\msdos\winsock\libldap.rc libraries\libldap\libldap.rc 
call copyback libraries\msdos\winsock\wsa\winsock.def libraries\libldap\winsock.def 

call copyback libraries\msdos\winsock\ldap32.def libraries\libldap\ldap32.def 
call copyback libraries\msdos\winsock\ldap32.mak libraries\libldap\ldap32.mak 
call copyback libraries\msdos\winsock\ldap32.mdp libraries\libldap\ldap32.mdp

call copyback libraries\libldap\getfilter.c libraries\libldap\getfilte.c
call copyback libraries\libldap\getvalues.c libraries\libldap\getvalue.c
call copyback include\proto-lber.h include\proto-lb.h
call copyback include\proto-ldap.h include\proto-ld.h

rmdir include\netinet
rmdir include\arpa
rmdir include\_sys
rmdir include\sys

goto END

:END


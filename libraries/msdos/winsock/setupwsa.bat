rem
rem MSDOS batch file to setup LDAP source area for Windows Socket API build
rem This should be run from the ***ROOT*** of the LDAP source tree
rem
rem Updated 4 April 1996 * Steve Rothwell * University of Michigan
rem

mkdir include\sys
mkdir include\_sys
mkdir include\arpa
mkdir include\netinet

rem  original set of empty files
copy libraries\msdos\winsock\include\file.h include\sys
copy libraries\msdos\winsock\include\select.h include\sys
copy libraries\msdos\winsock\include\socket.h include\sys
copy libraries\msdos\winsock\include\param.h include\sys
copy libraries\msdos\winsock\include\ioctl.h include\sys
copy libraries\msdos\winsock\include\filio.h include\sys
copy libraries\msdos\winsock\include\time.h include\sys
copy libraries\msdos\winsock\include\in.h include\netinet

rem  a newer copy
copy libraries\msdos\winsock\include\wsa\winsock.h include

rem  from MIT's kerberos stuff
copy libraries\msdos\winsock\include\krb\krb.h include
copy libraries\msdos\winsock\include\krb\des.h include

rem  from MIT's "localh" collection
copy libraries\msdos\winsock\include\krb\mit\mit_copy.h include
copy libraries\msdos\winsock\include\krb\mit\conf.h include
copy libraries\msdos\winsock\include\krb\mit\conf-pc.h include
copy libraries\msdos\winsock\include\krb\mit\osconf.h include
copy libraries\msdos\winsock\include\krb\mit\lsh_pwd.h include
copy libraries\msdos\winsock\include\krb\mit\wshelper.h include
copy libraries\msdos\winsock\include\krb\mit\resolv.h include
copy libraries\msdos\winsock\include\krb\mit\hesiod.h include
copy libraries\msdos\winsock\include\krb\mit\arpa\nameser.h include\arpa

rem  from Novell's LWP "toolkit" collection
copy libraries\msdos\winsock\include\net\_sys\filio.h include\_sys
copy libraries\msdos\winsock\include\net\_sys\ioctl.h include\_sys
copy libraries\msdos\winsock\include\net\netdb.h include

copy libraries\msdos\winsock\include\wsa.h include\msdos.h
copy libraries\msdos\winsock\wsa.c libraries\libldap\msdos.c

copy libraries\msdos\winsock\wsockip.c libraries\libldap
copy libraries\msdos\winsock\kerberos.c libraries\libldap

rem  the Pieces you need for MSVC 1.52c
copy libraries\msdos\winsock\libldap.def libraries\libldap
copy libraries\msdos\winsock\libldap.mak libraries\libldap
copy libraries\msdos\winsock\libldap.rc libraries\libldap
copy libraries\msdos\winsock\wsa\winsock.def libraries\libldap

copy libraries\msdos\winsock\ldap32.def libraries\libldap
copy libraries\msdos\winsock\ldap32.mak libraries\libldap
copy libraries\msdos\winsock\ldap32.mdp libraries\libldap

attrib -r libraries\libldap\getfilter.c
move libraries\libldap\getfilter.c libraries\libldap\getfilte.c
attrib -r  libraries\libldap\getvalues.c
move libraries\libldap\getvalues.c libraries\libldap\getvalue.c
attrib -r  include\proto-ldap.h
move include\proto-ldap.h include\proto-ld.h
attrib -r  include\proto-lber.h
move include\proto-lber.h include\proto-lb.h

$! 30-Nov-1995  ldap V3.2  Craig Watkins  Innosoft International, Inc.
$!
$! This is a crude make procedure to build the ldap libraries and the test
$! program.  This should work with DECC or VAXC compilers.
$!
$! This links with UCX libraries so that it should work on any TCP/IP
$! package that has UCX emulation.  This has been tested with MultiNet.
$! You may have to change the LINK to find your copy of UCX$IPC.OLB.
$!
$ ARCH = "VAX"
$ if f$getsyi("hw_model") .GE. 1024 then ARCH = "ALPHA"
$ !
$ ! If we are on an alpha/axp, we need to use DECC -- otherwise, your choice
$ COMPILER = "VAXC"
$ if ARCH .eqs. "ALPHA" then COMPILER = "DECC"
$ !
$ if COMPILER .eqs. "VAXC"
$ then
$   define arpa sys$library:
$   define sys sys$library:
$   define netinet sys$library:
$! This assumes your default compiler is VAXC; if not, add /VAXC below 
$   cc_switches = "/include=([---.include],[---.libraries.vms])/define=(LDAP_DEBUG,CLDAP,LDAP_REFERRALS,STR_TRANSLATION,LDAP_CHARSET_8859=88591)"
$!
$ else
$!
$   cc_switches = "/decc/standard=vaxc/include=([---.include],[---.libraries.vms])/define=(__STDC__,LDAP_DEBUG,CLDAP,LDAP_REFERRALS,STR_TRANSLATION,LDAP_CHARSET_8859=88591)
$ endif
$ !
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.liblber]io
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.liblber]encode
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.liblber]decode
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.liblber]version
$ !
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]ABANDON        
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]ADD            
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]ADDENTRY       
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]BIND           
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]CACHE          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]CHARSET
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]CLDAP          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]COMPARE        
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]DELETE         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]DISPTMPL       
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]DSPARSE        
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]ERROR          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]FREE           
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]FRIENDLY       
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETATTR        
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETDN          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETDXBYNAME
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETENTRY       
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETFILTER      
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]GETVALUES      
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]KBIND          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]MODIFY         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]MODRDN         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]OPEN           
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]OS-IP
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]REGEX          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]REQUEST          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]RESULT         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]SBIND          
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]SEARCH         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]SORT           
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]SRCHPREF       
$ cc 'CC_SWITCHES' 'P1' /define="TEMPLATEFILE=""LDAP_ETC:ldaptemplates.conf""" -
			[---.libraries.libldap]TMPLOUT        
$!CC 'CC_SWITCHES' 'P1' [---.libraries.libldap]TMPLTEST       
$ cc 'CC_SWITCHES' 'P1' /define="FILTERFILE=""LDAP_ETC:ldapfilter.conf""" -
			[---.libraries.libldap]UFN            
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]UNBIND         
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]VERSION        
$ !
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.vms]getopt
$ cc 'CC_SWITCHES' 'P1'  [---.libraries.vms]strings
$ !
$ library/create/log ldap.olb *.obj
$ !
$ cc 'CC_SWITCHES' 'P1' [---.libraries.libldap]TEST           
$ !
$ if COMPILER .eqs. "VAXC"
$ then
$!
$  link test, sys$input/opt
ldap.olb/lib
sys$library:ucx$ipc.olb/lib
sys$share:vaxcrtl.exe/share
$!
$ else
$!
$  link test, sys$input/opt
ldap.olb/lib
$ endif
$!

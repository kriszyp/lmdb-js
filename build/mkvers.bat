rem $OpenLDAP$
rem Copyright 1998-2003 The OpenLDAP Foundation
rem COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
rem of this package for details.
rem
rem Create a version.c file from build/version.h
rem

rem input, output, app, static

copy %1 %2
(echo. ) >> %2
(echo #include "portable.h") >> %2
(echo. ) >> %2
(echo %4 const char __Version[] =) >> %2
(echo "@(#) $" OPENLDAP_PACKAGE ": %3 " OPENLDAP_VERSION) >> %2
(echo " (" __DATE__ " " __TIME__ ") $\n") >> %2
(echo "\t%USERNAME%@%COMPUTERNAME% %CD:\=/%\n";) >> %2

:: $OpenLDAP$
:: Copyright 1998-2003 The OpenLDAP Foundation
:: COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
:: of this package for details.
::
:: Create a version.c file from build/version.h
::

:: usage: mkvers.bat <path/version.h>, <version.c>, <appname>, <static>

copy %1 %2
(echo. ) >> %2
(echo #include "portable.h") >> %2
(echo. ) >> %2
(echo %4 const char __Version[] =) >> %2
(echo "@(#) $" OPENLDAP_PACKAGE ": %3 " OPENLDAP_VERSION) >> %2
(echo " (" __DATE__ " " __TIME__ ") $\n") >> %2
(echo "\t%USERNAME%@%COMPUTERNAME% %CD:\=/%\n";) >> %2

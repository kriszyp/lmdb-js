PUSHDIVERT(-1)
## Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
## All rights reserved.
##
## Redistribution and use in source and binary forms are permitted only
## as authorized by the OpenLDAP Public License.  A copy of this
## license is available at http://www.OpenLDAP.org/license.html or
## in file LICENSE in the top-level directory of the distribution.
POPDIVERT

dnl
dnl mail500 mailer
dnl
dnl This file should be placed in the sendmail's cf/mailer directory.
dnl To include this mailer in your .cf file, use the directive:
dnl	MAILER(mail500)
dnl

ifdef(`MAIL500_HOST',
	`define(`MAIL500_HOST_FLAG', `')',
	`define(`MAIL500_HOST_FLAG', CONCAT(` -l ', CONCAT(MAIL500_HOST,` ')))')
ifdef(`MAIL500_MAILER_PATH',,
	`ifdef(`MAIL500_PATH',
		`define(`MAIL500_MAILER_PATH', MAIL500_PATH)',
		`define(`MAIL500_MAILER_PATH', /usr/local/libexec/mail500)')')
ifdef(`MAIL500_MAILER_FLAGS',,
	`define(`MAIL500_MAILER_FLAGS', `SmnXuh')')
ifdef(`MAIL500_MAILER_ARGS',,
	`define(`MAIL500_MAILER_ARGS',
		CONCAT(`mail500',CONCAT(MAIL500_HOST_FLAG,`-f $f -h $h -m $n@$w $u')))')
dnl

MAILER_DEFINITIONS

######################*****##############
###   MAIL500 Mailer specification   ###
##################*****##################

VERSIONID(`$OpenLDAP$')

Mmail500,	P=MAIL500_MAILER_PATH, F=CONCAT(`DFM', MAIL500_MAILER_FLAGS), S=11/31, R=20/40, T=DNS/RFC822/X-Unix,
		ifdef(`MAIL500_MAILER_MAX', `M=500_MAILER_MAX, ')A=MAIL500_MAILER_ARGS

LOCAL_CONFIG
# Mail500 Domains
#CQ foo.com

PUSHDIVERT(3)
# mail500 additions
R$* < @ $=Q > $*	$#mail500 $@ $2 $: <$1>		domain handled by mail500
POPDIVERT

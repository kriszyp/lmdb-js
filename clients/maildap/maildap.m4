PUSHDIVERT(-1)
## Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
## All rights reserved.
##
## Redistribution and use in source and binary forms are permitted only
## as authorized by the OpenLDAP Public License.  A copy of this
## license is available at http://www.OpenLDAP.org/license.html or
## in file LICENSE in the top-level directory of the distribution.

dnl
dnl maildap mailer
dnl
dnl This file should be placed in the sendmail's cf/mailer directory.
dnl To include this mailer in your .cf file, use the directive:
dnl	MAILER(maildap)
dnl

ifdef(`MAILDAP_HOST',
	`define(`MAILDAP_HOST_FLAG', CONCAT(` -l ', CONCAT(MAILDAP_HOST,` ')))',
	`define(`MAILDAP_HOST_FLAG', `')')
ifdef(`MAILDAP_CONFIG_PATH',,
	`define(`MAILDAP_CONFIG_PATH', /etc/mail/maildap.conf)')
ifdef(`MAILDAP_MAILER_PATH',,
	`ifdef(`MAILDAP_PATH',
		`define(`MAILDAP_MAILER_PATH', MAILDAP_PATH)',
		`define(`MAILDAP_MAILER_PATH', /usr/local/libexec/maildap)')')
ifdef(`MAILDAP_MAILER_FLAGS',,
	`define(`MAILDAP_MAILER_FLAGS', `SmnXuh')')
ifdef(`MAILDAP_MAILER_ARGS',,
	`define(`MAILDAP_MAILER_ARGS',
		CONCAT(`maildap',CONCAT(` -C ',MAILDAP_CONFIG_PATH,MAILDAP_HOST_FLAG,`-f $f -m $n@$w $u')))')

POPDIVERT

MAILER_DEFINITIONS

######################*****##############
###   MAILDAP Mailer specification   ###
##################*****##################

VERSIONID(`$OpenLDAP$')

Mmaildap,	P=MAILDAP_MAILER_PATH, F=CONCAT(`DFM', MAILDAP_MAILER_FLAGS), S=11/31, R=20/40, T=DNS/RFC822/X-Unix,
		ifdef(`MAILDAP_MAILER_MAX', `M=500_MAILER_MAX, ')A=MAILDAP_MAILER_ARGS

LOCAL_CONFIG
# Maildap Domains
#CQ foo.com

PUSHDIVERT(3)
# maildap additions
R$* < @ $=Q > $*	$#maildap $@ $2 $: <$1@$2>		domain handled by maildap
POPDIVERT

PUSHDIVERT(-1)
#
# mail500 mailer
#
# This file should be placed in the sendmail's cf/mailer directory.
# To include this mailer in your .cf file, use the directive:
#	MAILER(mail500)
#

#CQ foo.com

POPDIVERT

dnl
ifdef(`MAIL500_HOST',
	`define(`MAIL500_HOST_FLAG', CONCAT(` -l ', CONCAT(MAIL500_HOST,` ')))',
	`define(`MAIL500_HOST_FLAG', `')')
ifdef(`MAIL500_CONFIG_PATH',,
	`define(`MAIL500_CONFIG_PATH', /etc/mail/mail500.conf)')
ifdef(`MAIL500_MAILER_PATH',,
	`ifdef(`MAIL500_PATH',
		`define(`MAIL500_MAILER_PATH', MAIL500_PATH)',
		`define(`MAIL500_MAILER_PATH', /usr/local/libexec/mail500)')')
ifdef(`MAIL500_MAILER_FLAGS',,
	`define(`MAIL500_MAILER_FLAGS', `SmnXuh')')
ifdef(`MAIL500_MAILER_ARGS',,
	`define(`MAIL500_MAILER_ARGS',
		CONCAT(`mail500',CONCAT(` -C ',MAIL500_CONFIG_PATH,MAIL500_HOST_FLAG,`-f $f -m $n@$w $u')))')
dnl
MAILER_DEFINITIONS

VERSIONID(`OpenLDAP mail500 990630')

######################*****##############
###   MAIL500 Mailer specification   ###
##################*****##################

Mmail500,	P=MAIL500_MAILER_PATH, F=CONCAT(`DFM', MAIL500_MAILER_FLAGS), S=11/31, R=20/40, T=DNS/RFC822/X-Unix,
		ifdef(`MAIL500_MAILER_MAX', `M=500_MAILER_MAX, ')A=MAIL500_MAILER_ARGS

PUSHDIVERT(3)
# mail500 additions
R$* < @ $=Q > $*	$#mail500 $@ $2 $: <$1@$2>		domain handled by mail500
POPDIVERT

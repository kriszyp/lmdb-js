# $OpenLDAP$
#
# Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
#

all: build.txt

build.txt: version
	copy version build.txt

#! /bin/sh
# $OpenLDAP$
#
# Strip operational attributes
#
egrep -iv '^modifiersname:|^modifytimestamp:|^creatorsname:|^createtimestamp'

##
# Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
# COPYING RESTRICTIONS APPLY, see COPYRIGHT file
##

lib_LIBRARIES = libldapcpp.a
libldapcpp_a_SOURCES = LDAPAddRequest.cpp \
			LDAPAsynConnection.cpp \
			LDAPAttribute.cpp \
			LDAPAttributeList.cpp \
			LDAPBindRequest.cpp \
			LDAPCompareRequest.cpp \
			LDAPConstraints.cpp \
			LDAPControl.cpp \
			LDAPDeleteRequest.cpp \
			LDAPEntry.cpp \
			LDAPException.cpp \
			LDAPExtRequest.cpp \
			LDAPMessage.cpp \
			LDAPMessageQueue.cpp \
			LDAPModDNRequest.cpp \
			LDAPModification.cpp \
			LDAPModifyRequest.cpp \
			LDAPModList.cpp \
			LDAPReferral.cpp \
            LDAPRequest.cpp \
			LDAPResult.cpp \
			LDAPSearchReference.cpp \
			LDAPSearchRequest.cpp \
			LDAPSearchResult.cpp \
			LDAPUrl.cpp \
			LDAPUrlList.cpp 
			
bin_PROGRAMS = main

main_SOURCES = main.cpp
main_LDADD = ./libldapcpp.a



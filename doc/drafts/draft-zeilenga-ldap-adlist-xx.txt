





INTERNET-DRAFT                                      Kurt D. Zeilenga
Intended Category: Informational                    OpenLDAP Foundation
Expires in six months                               17 May 2002


              LDAPv3: Requesting Attributes by Object Class
                   <draft-zeilenga-ldap-adlist-01.txt>


Status of this Memo

  This document is an Internet-Draft and is in full conformance with all
  provisions of Section 10 of RFC2026.

  This document is intended to be, after appropriate review and
  revision, submitted to the RFC Editor as an Informational document.
  Distribution of this memo is unlimited.  Technical discussion of this
  document will take place on the IETF LDAP Extensions Working Group
  mailing list <ietf-ldapext@netscape.com>.  Please send editorial
  comments directly to the author <Kurt@OpenLDAP.org>.

  Internet-Drafts are working documents of the Internet Engineering Task
  Force (IETF), its areas, and its working groups.  Note that other
  groups may also distribute working documents as Internet-Drafts.
  Internet-Drafts are draft documents valid for a maximum of six months
  and may be updated, replaced, or obsoleted by other documents at any
  time.  It is inappropriate to use Internet-Drafts as reference
  material or to cite them other than as ``work in progress.''

  The list of current Internet-Drafts can be accessed at
  <http://www.ietf.org/ietf/1id-abstracts.txt>. The list of
  Internet-Draft Shadow Directories can be accessed at
  <http://www.ietf.org/shadow.html>.

  Copyright 2002, The Internet Society.  All Rights Reserved.

  Please see the Copyright section near the end of this document for
  more information.


Abstract

  The Lightweight Directory Access Protocol (LDAP) search operation
  provides mechanisms for clients to request all user application
  attributes, all operational attributes, or attributes selected by
  their description.  This document extends LDAP to provide a mechanism
  for LDAP clients to request the return of all attributes of an object
  class.



Zeilenga          Requesting Attributes by Object Class         [Page 1]

INTERNET-DRAFT        draft-zeilenga-ldap-adlist-01          17 May 2002


1.  Overview

  LDAP [RFC2251] search operations support mechanisms for requesting
  sets of attributes.  This set is determined by a list of attribute
  descriptions.  Two special descriptors are defined to request all user
  attributes ("*") and all operational attributes ("+").  However, there
  is no convenient mechanism for requesting pre-defined sets of
  attributes.  This document extends LDAP to allow an object class
  identifier to be specified in search request attributes list to
  request the return all attributes allowed by object class.

  The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
  "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
  document are to be interpreted as described in BCP 14 [RFC2119].


2.  Return of all Attributes of an Object Class

  This extension allows object class identifiers is to be provided in
  the attributes field of the LDAP SearchRequest [RFC2251].  For each
  object class identified in the attributes field, the request is to be
  treated as if each attribute allowed by that class (by "MUST" or
  "MAY", directly or by SUPerior) was itself listed.  For example, a
  request for "country" [RFC2256] is treated as if "c", "searchGuide",
  "description", and "objectClass" were requested.

  As a special case, requesting extensibleObject [RFC2252] is treated as
  if "objectClass,*,+" was requested [RFC2251][OPATTRS].

  If the object class identifier is unrecognized, it is be treated an an
  unrecognized attribute description.

  This extension redefines the attributes field of the SearchRequest to
  be a DescriptionList described by the following [ASN.1]:

       DescriptionList ::= SEQUENCE OF Description
       Description ::= LDAPString

  The Description is string conforming to the [ABNF]:

       Description ::= AttributeDescription | ObjectClassDescription.
       ObjectDescription ::= ObjectClass *( ";" options )

  where AttributeDescription and options productions are as defined in
  Section 4.1.5 of [RFC2251] and an ObjectClass is an objectIdentifier,
  in either numericoid or descr form [RFC 2252], of an object class.

  ObjectDescription options are provided for extensibility.  This



Zeilenga          Requesting Attributes by Object Class         [Page 2]

INTERNET-DRAFT        draft-zeilenga-ldap-adlist-01          17 May 2002


  document only defines semantics of ObjectDescriptions with zero
  options in the attributes field of a SearchRequest.  Other uses may be
  defined in future specifications.

  Servers supporting this feature SHOULD publish the Object Identifier
  1.3.6.1.4.1.4203.1.5.2 as a value of the supportedFeatures [FEATURES]
  attribute in the root DSE.


3.  Security Considerations

  This extension provides a shorthand for requesting all attributes of
  an object class.  As these attributes which could have been listed
  individually, this short hand is not believed to raises additional
  security considerations.

  Implementors of this (or any) LDAP extension should be familiar with
  general LDAP general security considerations [LDAPTS].


4.  IANA Considerations

  No IANA assignments are requested.

  This document uses the OID 1.3.6.1.4.1.4203.1.5.2 to identify the LDAP
  feature it details.  This OID was assigned [ASSIGN] by OpenLDAP
  Foundation under its IANA assigned private enterprise allocation
  [PRIVATE] for use in this specification.


5.  Author's Address

  Kurt D. Zeilenga
  OpenLDAP Foundation
  <Kurt@OpenLDAP.org>


6. Normative References

  [RFC2119]  S. Bradner, "Key words for use in RFCs to Indicate
             Requirement Levels", BCP 14 (also RFC 2119), March 1997.

  [RFC2251]  M. Wahl, T. Howes, S. Kille, "Lightweight Directory Access
             Protocol (v3)", RFC 2251, December 1997.

  [RFC2252]  M. Wahl, A. Coulbeck, T. Howes, S. Kille, "Lightweight
             Directory Access Protocol (v3):  Attribute Syntax
             Definitions", RFC 2252, December 1997.



Zeilenga          Requesting Attributes by Object Class         [Page 3]

INTERNET-DRAFT        draft-zeilenga-ldap-adlist-01          17 May 2002


  [LDAPTS]   J. Hodges, R. Morgan, "Lightweight Directory Access
             Protocol (v3): Technical Specification",
             draft-ietf-ldapbis-ldapv3-ts-xx.txt (a work in progress).

  [FEATURES] K. Zeilenga, "Feature Discovery in LDAP",
             draft-zeilenga-ldap-features-xx.txt (a work in progress).

  [OPATTRS]  K. Zeilenga, "LDAPv3: All Operational Attributes",
             draft-zeilenga-ldap-opattrs-xx.txt (a work in progress).


7. Informative References

  [RFC2256]  Wahl, M., "A Summary of the X.500(96) User Schema for use
             with LDAPv3", RFC 2256, December 1997.

  [X.500]    ITU-T Rec. X.500, "The Directory: Overview of Concepts,
             Models and Service", 1993.

  [X.511]    ITU-T Rec. X.511, "The Directory: Abstract Service
             Definition", 1993.

  [ASSIGN]   OpenLDAP Foundation, "OpenLDAP OID Delegations",
             http://www.openldap.org/foundation/oid-delegate.txt.

  [PRIVATE]  IANA, "Private Enterprise Numbers",
             http://www.iana.org/assignments/enterprise-numbers.



Copyright 2002, The Internet Society.  All Rights Reserved.

  This document and translations of it may be copied and furnished to
  others, and derivative works that comment on or otherwise explain it
  or assist in its implementation may be prepared, copied, published and
  distributed, in whole or in part, without restriction of any kind,
  provided that the above copyright notice and this paragraph are
  included on all such copies and derivative works.  However, this
  document itself may not be modified in any way, such as by removing
  the copyright notice or references to the Internet Society or other
  Internet organizations, except as needed for the  purpose of
  developing Internet standards in which case the procedures for
  copyrights defined in the Internet Standards process must be followed,
  or as required to translate it into languages other than English.

  The limited permissions granted above are perpetual and will not be
  revoked by the Internet Society or its successors or assigns.




Zeilenga          Requesting Attributes by Object Class         [Page 4]

INTERNET-DRAFT        draft-zeilenga-ldap-adlist-01          17 May 2002


  This document and the information contained herein is provided on an
  "AS IS" basis and THE AUTHORS, THE INTERNET SOCIETY, AND THE INTERNET
  ENGINEERING TASK FORCE DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED,
  INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE
  INFORMATION HEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED
  WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.













































Zeilenga          Requesting Attributes by Object Class         [Page 5]


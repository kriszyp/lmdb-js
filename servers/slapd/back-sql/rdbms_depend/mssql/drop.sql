
if exists (select * from sysobjects where id = object_id(N'ldap_attrs') and OBJECTPROPERTY(id, N'IsUserTable') = 1)
drop table ldap_attrs
GO

if exists (select * from sysobjects where id = object_id(N'ldap_entries') and OBJECTPROPERTY(id, N'IsUserTable') = 1)
drop table ldap_entries
GO

if exists (select * from sysobjects where id = object_id(N'ldap_objclasses') and OBJECTPROPERTY(id, N'IsUserTable') = 1)
drop table ldap_objclasses
GO


drop table ldap_oc_mappings;
create table ldap_oc_mappings
 (
	id integer not null primary key,
	name varchar(64) not null,
	keytbl varchar(64) not null,
	keycol varchar(64) not null,
	create_proc varchar(255),
	delete_proc varchar(255),
	expect_return int not null
);

drop table ldap_attr_mappings;
create table ldap_attr_mappings
 (
	id integer not null primary key,
	oc_map_id integer not null references ldap_oc_mappings(id),
	name varchar(255) not null,
	sel_expr varchar(255) not null,
	sel_expr_u varchar(255),
	from_tbls varchar(255) not null,
	join_where varchar(255),
	add_proc varchar(255),
	delete_proc varchar(255),
	param_order int not null,
	expect_return int not null
);

drop table ldap_entries;
create table ldap_entries
 (
	id integer not null primary key,
	dn varchar(255) not null,
	oc_map_id integer not null references ldap_oc_mappings(id),
	parent int NOT NULL,
	keyval int NOT NULL,
	UNIQUE ( oc_map_id, keyval ),
	UNIQUE ( dn )
);

drop table ldap_referrals;
create table ldap_referrals
 (
	entry_id integer not null references ldap_entries(id),
	url text not null
);

drop table ldap_entry_objclasses;
create table ldap_entry_objclasses
 (
	entry_id integer not null references ldap_entries(id),
	oc_name varchar(64)
 );

----- Apparently PostgreSQL 7.0 does not know concat(); however,
----- back-sql can be configured to use '||' for string concatenation.
----- Those who can't live without concat() can uncomment this:
-- drop function concat(text, text);
-- create function concat(text, text) returns text as 'select $1 || $2;' language 'sql';


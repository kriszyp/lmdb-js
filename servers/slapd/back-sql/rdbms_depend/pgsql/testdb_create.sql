drop table persons;
drop sequence persons_id_seq;
create table persons (
	id serial not null primary key,
	name varchar(255) not null,
	surname varchar(255) not null
);

drop table institutes;
drop sequence institutes_id_seq;
create table institutes (
	id serial not null primary key,
	name varchar(255)
);

drop table documents;
drop sequence documents_id_seq;
create table documents (
	id serial not null primary key,
	title varchar(255) not null,
	abstract varchar(255)
);

drop table authors_docs;
create table authors_docs (
	pers_id int not null,
	doc_id int not null,
	primary key ( pers_id, doc_id )
);

drop table phones;
drop sequence phones_id_seq;
create table phones (
	id serial not null primary key,
	phone varchar(255) not null ,
	pers_id int not null
);


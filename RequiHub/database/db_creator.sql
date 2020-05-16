-- Script para montar la DB
drop database if exists firstApp;

create database firstApp;

use firstApp;

create table users(
	id int primary key auto_increment,
	first_name varchar(40) default '' not null,
	last_name varchar(40) default '' not null,
	email varchar(40) default '' not null,
	password text not null,
	created date
);

alter table users auto_increment = 1;

GRANT ALL PRIVILEGES ON firstApp.* TO 'administrador'@'%' IDENTIFIED BY 'abnormalize';
FLUSH PRIVILEGES;
#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for auth basic module.

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http mysql/)->plan(6)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

	error_log /tmp/error.log warn;
	location / {
            # Enable MySQL authentication
            auth_mysql_host    "127.0.0.1";
            auth_mysql_user    "root";
            auth_mysql_password "root";
            auth_mysql_database "nginx_mysql";
            auth_mysql_table "users";
            auth_mysql_user_column "user_login";
            auth_mysql_password_column "user_pass";
            auth_mysql_encryption_type "bcrypt";
            auth_mysql_realm "Test";
            try_files $uri $uri/ =403;
        }
    }
}

EOF

$t->write_file('index.html', 'SEETHIS');
chmod 0644, $t->testdir . '/index.html';
chmod 0755, $t->testdir;
$t->run();

###############################################################################

like(http_get('/'), qr!401 Unauthorized!ms, 'rejects unathorized');
like(http_get_auth('/', 'test1', 'password'), qr!SEETHIS!, 'phpass $P$');
like(http_get_auth('/', 'test2', 'password'), qr!SEETHIS!, 'bcrypt $2y$');
like(http_get_auth('/', 'test3', 'password'), qr!SEETHIS!, 'WP bcrypt $wp$');
like(http_get_auth('/', 'test1', 'password11'), qr!401 Unauthorized!, 'invalid test1 password');
like(http_get_auth('/', 'crypt2', '1'), qr!401 Unauthorized!, 'invalid user');

###############################################################################

sub http_get_auth {
	my ($url, $user, $password) = @_;

	my $auth = encode_base64($user . ':' . $password, '');

	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Authorization: Basic $auth

EOF
}

###############################################################################

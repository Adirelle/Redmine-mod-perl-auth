package Apache::Authn::Redmine;

=head1 Apache::Authn::Redmine

Redmine - a mod_perl module to authenticate webdav subversion users
against redmine database

=head1 SYNOPSIS

This module allow anonymous users to browse public project and
registred users to browse and commit their project. Authentication is
done against the redmine database or the LDAP configured in redmine.

This method is far simpler than the one with pam_* and works with all
database without an hassle but you need to have apache/mod_perl on the
svn server.

=head1 INSTALLATION

For this to automagically work, you need to have a recent reposman.rb
(after r860) and if you already use reposman, read the last section to
migrate.

Sorry ruby users but you need some perl modules, at least mod_perl2,
DBI and DBD::mysql (or the DBD driver for you database as it should
work on allmost all databases).

On debian/ubuntu you must do :

	aptitude install libapache-dbi-perl libapache2-mod-perl2 libdbd-mysql-perl

If your Redmine users use LDAP authentication, you will also need
Authen::Simple::LDAP (and IO::Socket::SSL if LDAPS is used):

	aptitude install libauthen-simple-ldap-perl libio-socket-ssl-perl

=head1 CONFIGURATION

	## This module has to be in your perl path
	## eg:  /usr/lib/perl5/Apache/Authn/Redmine.pm
	PerlLoadModule Apache::Authn::Redmine
	<Location /svn>
		DAV svn
		SVNParentPath "/var/svn"

		AuthType Basic
		AuthName redmine
		Require valid-user

		PerlAuthenHandler Apache::Authn::Redmine::authen_handler
		PerlAuthzHandler Apache::Authn::Redmine::authz_handler

		## for mysql
		RedmineDSN "DBI:mysql:database=databasename;host=my.db.server"
		## for postgres
		# RedmineDSN "DBI:Pg:dbname=databasename;host=my.db.server"

		RedmineDbUser "redmine"
		RedmineDbPass "password"

		## Authorization where clause (fulltext search would be slow and database dependant).
		## Default: none
		# RedmineDbWhereClause "and members.role_id IN (1,2)"

		## SCM transport protocol, used to detecte write requests
		## Valid values: Subversion, Git, None
		## Default: Subversion
		# RedmineRepositoryType Subversion

		## Credentials cache size
		## Default: 0 (disabled)
		# RedmineCacheCredsMax 50

		## Credentials cache expiration delay in seconds
		## Set to 0 to disable expiration.
		## Default: 5 minutes (300)
		# RedmineCacheCredsMaxAge 60

		## Check authorizations against a specific project.
		## Default: none (extract project from location)
		# RedmineProject myproject

		## Permissions to check for "read" access.
		## You can add several permissions, user is granted access if *at least* one them exists.
		## Default: :browse_repository
		# RedmineReadPermissions :browse_repository

		## Permissions to check for "write" access.
		## You can add several permissions, user is granted access if *at least* one them exists.
		## Default: :commit_access
		# RedmineWritePermissions :commit_access

		## Deny anonymous access.
		## Affects both authentication and authorization
		## Default: Off
		# RedmineDenyAnonymous On

		## Deny non-member access to projects.
		## Default: Off
		# RedmineDenyNonMember On

		## Administrators have super-powers
		## Default: On
		# RedmineSuperAdmin Off

	</Location>

To be able to browse repository inside redmine, you must add something
like that :

	<Location /svn-private>
		DAV svn
		SVNParentPath "/var/svn"
		Order deny,allow
		Deny from all
		# only allow reading orders
		<Limit GET PROPFIND OPTIONS REPORT>
			Allow from redmine.server.ip
		</Limit>
	</Location>

and you will have to use this reposman.rb command line to create repository :

	reposman.rb --redmine my.redmine.server --svn-dir /var/svn --owner www-data -u http://svn.server/svn-private/

=head1 MIGRATION FROM OLDER RELEASES

If you use an older reposman.rb (r860 or before), you need to change
rights on repositories to allow the apache user to read and write
S<them :>

	sudo chown -R www-data /var/svn/*
	sudo chmod -R u+w /var/svn/*

And you need to upgrade at least reposman.rb (after r860).

=cut

use strict;
use warnings FATAL => 'all', NONFATAL => 'redefine';

use DBI;
use Digest::SHA;
# optional module for LDAP authentication
my $CanUseLDAPAuth = eval("use Authen::Simple::LDAP; 1");

# Reload ourself (disable in production)
# use Apache2::Reload;

use Apache2::Module;
use Apache2::Access;
use Apache2::ServerRec qw();
use Apache2::RequestRec qw();
use Apache2::RequestUtil qw();
use Apache2::CmdParms qw();
use Apache2::Const qw(:common :override :cmd_how);
use Apache2::Log;
use APR::Pool ();
use APR::Table ();

# use Apache2::Directive qw();

my @directives = (
	{
		name         => 'RedmineDSN',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Redmine database DSN in format used by Perl DBI. eg: "DBI:Pg:dbname=databasename;host=my.db.server"',
	},
	{
		name         => 'RedmineDbUser',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Redmine database user',
	},
	{
		name         => 'RedmineDbPass',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Redmine database password',
	},
	{
		name         => 'RedmineDbWhereClause',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Additionnal where clause used when checking for user permissions',
	},
	{
		name         => 'RedmineProject',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Identifier (short name) of a Redmine project. If undefined, extract the project identifier from the location.',
	},
	{
		name         => 'RedmineReadPermissions',
		req_override => OR_AUTHCFG,
		args_how     => ITERATE,
		errmsg       => 'Permissions to check for read access. Defaults to :browse_repository.',
	},
	{
		name         => 'RedmineWritePermissions',
		req_override => OR_AUTHCFG,
		args_how     => ITERATE,
		errmsg       => 'Permissions to check for write access. Defaults to :commit_access.',
	},
	{
		name         => 'RedmineCacheCredsMax',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Maximum number of credentials to cache. Set to 0 to disable credential caching.',
	},
	{
		name         => 'RedmineCacheCredsMaxAge',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Maximum age of cached credentials. Defaults to 300. Set to 0 to disable credential expiration.',
	},
	{
		name         => 'RedmineDenyAnonymous',
		req_override => OR_AUTHCFG,
		args_how     => FLAG,
		errmsg       => 'Deny anonymous access. Defaults to no.',
	},
	{
		name         => 'RedmineDenyNonMember',
		req_override => OR_AUTHCFG,
		args_how     => FLAG,
		errmsg       => 'Do not check non-member permissions. Defaults to no.',
	},
	{
		name         => 'RedmineSuperAdmin',
		req_override => OR_AUTHCFG,
		args_how     => FLAG,
		errmsg       => 'Grant all permissions to administrators. Defaults to yes.',
	},
	{
		name         => 'RedmineRepositoryType',
		req_override => OR_AUTHCFG,
		args_how     => TAKE1,
		errmsg       => 'Indicate the type of Repository (Subversion or Git or None). This is used to properly detected write requests. Defaults to Subversion.',
	},
	{
		name         => 'RedmineSetUserAttributes',
		req_override => OR_AUTHCFG,
		args_how     => FLAG,
		errmsg       => 'Sets firstname, lastname, email address to environment variables. Defaults to no.',
	},
);

# Initialize defaults configuration
sub DIR_CREATE {
	my($class, $parms) = @_;
	my $identifier_re = "^".quotemeta($parms->path)."/?([^/]+)" if $parms->path;
	return bless {
		PermissionQuery => trim("
			SELECT permissions FROM users, members, member_roles, roles
			WHERE users.login = ?
				AND users.id = members.user_id
				AND users.status = 1
				AND	members.project_id = ?
				AND members.id = member_roles.member_id
				AND member_roles.role_id = roles.id
		"),
		RepositoryType   => 'Subversion',
		IdentifierRegex  => $identifier_re ? qr{$identifier_re} : undef,
		CacheCredsMax    => 0,
		CacheCredsCount  => 0,
		CacheCredsMaxAge => 300,
		DenyAnonymous    => 0,
		DenyNonMember    => 0,
		SuperAdmin       => 1,
		SetUserAttributes => 0,
		AttributesCacheCredsCount  => 0,
	}, $class;
}

# Simple setters
sub RedmineDSN { set_val('DSN', @_); }
sub RedmineDbUser { set_val('DbUser', @_); }
sub RedmineDbPass { set_val('DbPass', @_); }
sub RedmineProject { set_val('Project', @_); }
sub RedmineReadPermissions  { push_val('ReadPermissions', @_); }
sub RedmineWritePermissions { push_val('WritePermissions', @_); }
sub RedmineCacheCredsMax { set_val('CacheCredsMax', @_); }
sub RedmineCacheCredsMaxAge { set_val('CacheCredsMaxAge', @_); }
sub RedmineDenyAnonymous { set_val('DenyAnonymous', @_); }
sub RedmineDenyNonMember { set_val('DenyNonMember', @_); }
sub RedmineSuperAdmin { set_val('SuperAdmin', @_); }
sub RedmineSetUserAttributes { set_val('SetUserAttributes', @_); }

sub RedmineDbWhereClause {
	my ($cfg, $parms, $arg) = @_;
	if($arg) {
		$cfg->{PermissionQuery} = trim($cfg->{PermissionQuery}."$arg ");
	}
}

sub RedmineRepositoryType {
	my ($cfg, $parms, $arg) = @_;
	$arg = trim($arg);
	if($arg eq 'Subversion' || $arg eq 'Git') {
		$cfg->{RepositoryType} = 'Repository::'.$arg;
	} elsif($arg eq 'None') {
		$cfg->{RepositoryType} = $arg;
	} else {
		die "Invalid RedmineRepositoryType value: $arg, choose either Subversion or Git or None !";
	}
}


sub set_val {
	my ($key, $cfg, $parms, $arg) = @_;
	$cfg->{$key} = $arg;
}

sub push_val {
	my ($key, $cfg, $parms, $arg) = @_;
	push @{ $cfg->{$key} }, $arg;
}

sub trim {
	my $string = shift;
	$string =~ s/\s{2,}/ /g;
	return $string;
}

Apache2::Module::add(__PACKAGE__, \@directives);

my %read_only_methods = map { $_ => 1 } qw/GET PROPFIND REPORT OPTIONS/;
my @default_read_permissions = ( ':browse_repository' );
my @default_write_permissions = ( ':commit_access' );

sub authen_handler {
	my $r = shift;

	unless ($r->some_auth_required) {
			$r->log_reason("No authentication has been configured");
			return FORBIDDEN;
	}

	my ($res, $password) = $r->get_basic_auth_pw();
	my $reason;

	if($res == OK) {
		# Got user and password

		#	Used cached credentials if possible
		my $cache_key = get_cache_key($r, $password);
		my $cfg = get_config($r);
		if(defined $cache_key && !$cfg->{SetUserAttributes} && cache_get($r, $cache_key)) {
			$r->log->debug("reusing cached credentials for user '", $r->user, "'");
			$r->set_handlers(PerlAuthzHandler => undef);
			attributes_cache_get($r, $cache_key);

		} elsif(defined $cache_key && $cfg->{SetUserAttributes} && cache_get($r, $cache_key) && attributes_cache_get($r, $cache_key)) {
			$r->log->debug("reusing cached credentials for user '", $r->user, "' including attributes");
			$r->set_handlers(PerlAuthzHandler => undef);

		} else {
			# Else check them
			my $dbh = connect_database($r)
				or return SERVER_ERROR;

			($res, $reason) = check_login($r, $dbh, $password);
			$dbh->disconnect();

			# Store the cache key for latter use
			$r->pnotes("RedmineCacheKey" => $cache_key) if $res == OK && defined $cache_key;
		}

	} elsif($res == AUTH_REQUIRED) {
		my $dbh = connect_database($r)
			or return SERVER_ERROR;

		my $cfg = get_config($r);

		if(!$cfg->{AllowAnonymous} || is_authentication_forced($dbh)) {
			# We really want an user
			$reason = 'anonymous access disabled';
		} else {
			# Anonymous is allowed
			$res = OK;
		}
		$dbh->disconnect();

	}

	$r->log_reason($reason) if defined($reason);
	$r->note_basic_auth_failure unless $res == OK;

	return $res;
}


sub check_login {
	my ($r, $dbh, $password) = @_;
	my $user = $r->user;

	my ($hashed_password, $status, $auth_source_id, $salt, $id, $firstname, $lastname) = $dbh->selectrow_array('SELECT hashed_password, status, auth_source_id, salt, id, firstname, lastname FROM users WHERE login = ?', undef, $user)
		or return (AUTH_REQUIRED, "unknown user '$user'");

	# Check password
	if($auth_source_id) {
		# LDAP authentication

		# Ensure Authen::Simple::LDAP is available
		return (SERVER_ERROR, "Redmine LDAP authentication requires Authen::Simple::LDAP")
			unless $CanUseLDAPAuth;

		# Get LDAP server informations
		my($host, $port, $tls, $account, $account_password, $base_dn, $attr_login) = $dbh->selectrow_array(
			"SELECT host,port,tls,account,account_password,base_dn,attr_login from auth_sources WHERE id = ?",
			undef,
			$auth_source_id
		)
			or return (SERVER_ERROR, "Undefined authentication source for '$user'");

		# Connect to the LDAP server
		my $ldap = Authen::Simple::LDAP->new(
				host    =>      is_true($tls) ? "ldaps://$host:$port" : $host,
				port    =>      $port,
				basedn  =>      $base_dn,
				binddn  =>      $account || "",
				bindpw  =>      $account_password || "",
				filter  =>      '('.$attr_login.'=%s)'
		);

		# Finally check user login
		return (AUTH_REQUIRED, "LDAP authentication failed (user: '$user', server: '$host')")
			unless $ldap->authenticate($user, $password);

	} else {
		# Database authentication
		my $pass_digest = Digest::SHA::sha1_hex($password);
		return (AUTH_REQUIRED, "wrong password for '$user'")
			unless $hashed_password eq Digest::SHA::sha1_hex($salt.$pass_digest);
	}

	# Password is ok, check if account if locked
	return (FORBIDDEN, "inactive account: '$user'") unless $status == 1;

	my($email_address) = $dbh->selectrow_array(
		"SELECT address
		FROM email_addresses
		WHERE email_addresses.user_id=? and is_default=1",
		undef, 
		$id
	);
	if (defined $email_address) {
		$r->subprocess_env->set("REDMINE_DEFAULT_EMAIL_ADDRESS" => $email_address);
	} else {
		$r->subprocess_env->set("REDMINE_DEFAULT_EMAIL_ADDRESS" => "");
	}
	$r->subprocess_env->set("REDMINE_FIRSTNAME" => $firstname);
	$r->subprocess_env->set("REDMINE_LASTNAME" => $lastname);
	$r->log->debug("successfully authenticated as active redmine user '$user'");

	# Everything's ok
	return OK;
}

# check if authentication is forced
sub is_authentication_forced {
	my $dbh = shift;
	return is_true($dbh->selectrow_array("SELECT value FROM settings WHERE settings.name = 'login_required'"));
}

sub authz_handler {
	my $r = shift;

	unless ($r->some_auth_required) {
			$r->log_reason("No authentication has been configured");
			return FORBIDDEN;
	}

	my $dbh = connect_database($r)
		or return SERVER_ERROR;

	my $cfg = get_config($r);

	my ($identifier, $project_id, $is_public, $status);

	if($identifier = $cfg->{Project} and $cfg->{RepositoryType} ne 'None') {
		($project_id, $is_public, $status) = $dbh->selectrow_array(
			"SELECT p.id, p.is_public, p.status
			FROM projects p JOIN repositories r ON (p.id = r.project_id)
			WHERE p.identifier = ? AND r.is_default AND r.type = ?",
			undef, $identifier, $cfg->{RepositoryType}
		);
		unless(defined $project_id) {
			$r->log_reason("No matching project for ${identifier}");
			return NOT_FOUND;
		}

	} elsif($identifier = $cfg->{Project} and $cfg->{RepositoryType} eq 'None') {
		($project_id, $is_public, $status) = $dbh->selectrow_array(
			"SELECT p.id, p.is_public, p.status
			FROM projects p
			WHERE p.identifier = ?",
			undef, $identifier
		);
		unless(defined $project_id) {
			$r->log_reason("No matching project for ${identifier}");
			return NOT_FOUND;
		}

	} elsif($cfg->{RepositoryType} ne 'None' and my $repo_id = get_repository_identifier($r)) {
		($identifier, $project_id, $is_public, $status) = $dbh->selectrow_array(
			"SELECT p.identifier, p.id, p.is_public, p.status
			FROM projects p JOIN repositories r ON (p.id = r.project_id)
			WHERE ((r.is_default AND p.identifier = ?) OR r.identifier = ?) AND r.type = ?",
			undef, $repo_id, $repo_id, $cfg->{RepositoryType}
		);
		unless(defined $project_id) {
			$r->log_reason("No matching project for ${repo_id}");
			return NOT_FOUND;
		}

	} else {
		# Cannot get a project out of the URL, we probably are on the parent path (e.g. /svn/)
		return FORBIDDEN;
	}

	$is_public = is_true($is_public);

	my($res, $reason) = FORBIDDEN;

	if($status != 1 && !is_read_request($r)) {
		# Write operation on archived project is forbidden
		$reason = "write operations on inactive project '$identifier' are forbidden";

	} elsif(!$r->user) {
		# Anonymous access
		$res = AUTH_REQUIRED;
		$reason = "anonymous access to '$identifier' denied";

		if($is_public && !$cfg->{DenyAnonymous}) {
			# Check anonymous permissions
			my $permissions = $dbh->selectrow_array("SELECT permissions FROM roles WHERE builtin = 2");
			$res = OK if $permissions && check_permissions($r, $permissions);
		}

		# Force login if failed
		$r->note_auth_failure unless $res == OK;

	} else {
		# Logged in user
		my $user = $r->user;

		if($cfg->{SuperAdmin} && is_true($dbh->selectrow_array("SELECT admin FROM users WHERE login = ?", undef, $user))) {
			# Adminstrators have all the rights
			$res = OK;

		} else {
			# Really check user permissions
			my @permissions = ();

			# Membership permissions
			my $membership = $dbh->selectcol_arrayref($cfg->{PermissionQuery}, undef, $user, $project_id);
			push @permissions, @{$membership} if $membership;

			# Add non-member permissions for public projects
			if($is_public && !$cfg->{DenyNonMember}) {
				my $non_member = $dbh->selectrow_array("SELECT permissions FROM roles WHERE builtin = 1");
				push @permissions, $non_member if $non_member;
			}

			# Look for the permissions
			$res = OK if check_permissions($r, @permissions);
		}

		if($res == OK) {
			# Put successful credentials in cache
			if(my $cache_key = $r->pnotes("RedmineCacheKey")) {
				cache_set($r, $cache_key);
				attributes_cache_set($r, $cache_key);
			}

		} else {
			$reason = "insufficient permissions (user: '$user', project: '$identifier')";
		}
	}

	# Log what we have done
	if($res == OK) {
		$r->log->debug("access granted: user '", ($r->user || 'anonymous'), "', project '$identifier', method: '", $r->method, "'") if $res == OK;
	} elsif(defined $reason) {
		$r->log_reason($reason);
	}

	$dbh->disconnect();

	return $res;
}

# get the repository identifier from the URI
sub get_repository_identifier {
	my ($r) = @_;
	my $cfg = get_config($r);
	my($identifier) = ($r->uri =~ $cfg->{IdentifierRegex}) if defined $cfg->{IdentifierRegex};
	return $identifier;
}

# tell if the given request is a read operation
sub is_read_request {
	my $r = shift;

	my $cfg = get_config($r);
	if($cfg->{RepositoryType} eq "Subversion") {
		return defined $read_only_methods{$r->method};
	} else {
		return $r->unparsed_uri !~ m@[=/]git-receive-pack@;
	}
}

# check if one of the required permissions is in the passed list
sub check_permissions {
	my $r = shift;

	my $permissions = join(' ', @_)
		or return 0;

	my $cfg = get_config($r);
	my @required;
	if(is_read_request($r)) {
		@required = $cfg->{ReadPermissions} || @default_read_permissions;
	} else {
		@required = $cfg->{WritePermissions} || @default_write_permissions;
	}

	foreach (@required) {
		return 1 if $permissions =~ m{\Q$_\E};
	}

	return 0;
}

# return module configuration for current directory
sub get_config {
	my $r = shift;

	return Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);
}

# get a connection to the redmine database
sub connect_database {
	my $r = shift;

	my $cfg = get_config($r);
	my $dbh = DBI->connect($cfg->{DSN}, $cfg->{DbUser}, $cfg->{DbPass}, {
		pg_enable_utf8 => 1,
		mysql_enable_utf8 => 1,
	})
		or $r->log->error("Connection to database failed: $DBI::errstr.");

	return $dbh;
}

# tell if a value returned from SQL is "true"
sub is_true {
	my $value = shift;
	return defined($value) && ($value == 1 || $value eq "t");
}

# build credential cache key
sub get_cache_key {
	my ($r, $password) = @_;
	my $identifier = get_config($r)->{Project} || get_repository_identifier($r)
		or return;
	return Digest::SHA::sha1_hex(join(':', $identifier, $r->user, $password, is_read_request($r) ? 'read' : 'write'));
}

# check if credentials exist in cache
sub cache_get {
	my($r, $key) = @_;

	my $cfg = get_config($r);
	return unless $cfg->{CacheCredsMax} && $cfg->{CacheCreds};

	my $time = $cfg->{CacheCreds}->get($key)
		or return 0;

	if($cfg->{CacheCredsMaxAge} && ($r->request_time - $time) > $cfg->{CacheCredsMaxAge}) {
		$cfg->{CacheCreds}->unset($key);
		$cfg->{CacheCredsCount}--;
		return 0;
	}
	return 1;
}

sub attributes_cache_get {
	my($r, $key) = @_;

	my $cfg = get_config($r);
	return unless $cfg->{CacheCredsMax} && $cfg->{AttributesCacheCreds};

	my $cache_text = $cfg->{AttributesCacheCreds}->get($key)
		or return 0;

	$r->log->error("cache_text:$cache_text");
	my($time, $email_address, $firstname, $lastname) = split(":", $cache_text);
	if($cfg->{CacheCredsMaxAge} && ($r->request_time - $time) > $cfg->{CacheCredsMaxAge}) {
		$cfg->{AttributesCacheCreds}->unset($key);
		$cfg->{AttributesCacheCredsCount}--;
		return 0;
	}

	$r->subprocess_env->set("REDMINE_DEFAULT_EMAIL_ADDRESS", $email_address . "");
	$r->subprocess_env->set("REDMINE_FIRSTNAME", $firstname . "");
	$r->subprocess_env->set("REDMINE_LASTNAME", $lastname . "");

	return 1;
}

# put credentials in cache
sub cache_set {
	my($r, $key) = @_;

	my $cfg = get_config($r);
	return unless $cfg->{CacheCredsMax};

	unless($cfg->{CacheCreds}) {
		$cfg->{CachePool} = APR::Pool->new;
		$cfg->{CacheCreds} = APR::Table::make($cfg->{CachePool}, $cfg->{CacheCredsMax});
	}

	if($cfg->{CacheCredsCount} >= $cfg->{CacheCredsMax}) {
		$cfg->{CacheCreds}->clear;
		$cfg->{CacheCredsCount} = 0;
	}
	$cfg->{CacheCreds}->set($key, $r->request_time);
	$cfg->{CacheCredsCount}++;
}

sub attributes_cache_set {
	my($r, $key) = @_;

	my $cfg = get_config($r);
	return unless $cfg->{CacheCredsMax};

	unless($cfg->{AttributesCacheCreds}) {
		$cfg->{AttributesCachePool} = APR::Pool->new;
		$cfg->{AttributesCacheCreds} = APR::Table::make($cfg->{AttributesCachePool}, $cfg->{CacheCredsMax});
	}

	if($cfg->{AttributesCacheCredsCount} >= $cfg->{CacheCredsMax}) {
		$cfg->{AttributesCacheCreds}->clear;
		$cfg->{AttributesCacheCredsCount} = 0;
	}
	my $cache_text = join(":", $r->request_time,
		$r->subprocess_env->get("REDMINE_DEFAULT_EMAIL_ADDRESS"),
		$r->subprocess_env->get("REDMINE_FIRSTNAME"),
		$r->subprocess_env->get("REDMINE_LASTNAME"),
	);
	$cfg->{AttributesCacheCreds}->set($key, $cache_text);
	$cfg->{AttributesCacheCredsCount}++;
}

1;



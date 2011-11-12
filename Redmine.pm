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
     ## Optional where clause (fulltext search would be slow and
     ## database dependant).
     # RedmineDbWhereClause "and members.role_id IN (1,2)"
     ## Optional credentials cache size
     # RedmineCacheCredsMax 50
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
use Digest::SHA1;
# optional module for LDAP authentication
my $CanUseLDAPAuth = eval("use Authen::Simple::LDAP; 1");

# Reload ourself (disable in production)
use Apache2::Reload;

use Apache2::Module;
use Apache2::Access;
use Apache2::ServerRec qw();
use Apache2::RequestRec qw();
use Apache2::RequestUtil qw();
use Apache2::Const qw(:common :override :cmd_how);
use Apache2::Log;
use APR::Pool ();
use APR::Table ();

# use Apache2::Directive qw();

my @directives = (
  {
    name => 'RedmineDSN',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
    errmsg => 'Dsn in format used by Perl DBI. eg: "DBI:Pg:dbname=databasename;host=my.db.server"',
  },
  {
    name => 'RedmineDbUser',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
  },
  {
    name => 'RedmineDbPass',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
  },
  {
    name => 'RedmineDbWhereClause',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
  },
  {
    name => 'RedmineCacheCredsMax',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
    errmsg => 'RedmineCacheCredsMax must be decimal number',
  },
  {
    name => 'RedmineCacheCredsMaxAge',
    req_override => OR_AUTHCFG,
    args_how => TAKE1,
    errmsg => 'RedmineCacheCredsMaxAge must be decimal number',
  },
);

sub RedmineDSN { 
  my ($self, $parms, $arg) = @_;
  $self->{RedmineDSN} = $arg;
  my $query = "SELECT 
                 hashed_password, salt, auth_source_id, permissions
              FROM members, projects, users, roles, member_roles
              WHERE 
                projects.id=members.project_id
                AND member_roles.member_id=members.id
                AND users.id=members.user_id 
                AND roles.id=member_roles.role_id
                AND users.status=1 
                AND login=? 
                AND identifier=? ";
  $self->{RedmineQuery} = trim($query);
}

sub RedmineDbUser { set_val('RedmineDbUser', @_); }
sub RedmineDbPass { set_val('RedmineDbPass', @_); }
sub RedmineDbWhereClause { 
  my ($self, $parms, $arg) = @_;
  $self->{RedmineQuery} = trim($self->{RedmineQuery}.($arg ? $arg : "")." ");
}

sub RedmineCacheCredsMax { 
  my ($self, $parms, $arg) = @_;
  if ($arg) {
    $self->{RedmineCachePool} = APR::Pool->new;
    $self->{RedmineCacheCreds} = APR::Table::make($self->{RedmineCachePool}, $arg);
    $self->{RedmineCacheCredsCount} = 0;
    $self->{RedmineCacheCredsMax} = $arg;
  }
}

sub RedmineCacheCredsMaxAge { set_val('RedmineCacheCredsMaxAge', @_); }

sub trim {
  my $string = shift;
  $string =~ s/\s{2,}/ /g;
  return $string;
}

sub set_val {
  my ($key, $self, $parms, $arg) = @_;
  $self->{$key} = $arg;
}

Apache2::Module::add(__PACKAGE__, \@directives);

my %read_only_methods = map { $_ => ':browse_repository' } qw/GET PROPFIND REPORT OPTIONS/;

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
		if(cache_get($r, $cache_key)) {
			$r->log->debug("reusing cached credentials for user '", $r->user, "'");
			$r->set_handlers(PerlAuthzHandler => undef);
			
		} else {
			# Else check them
			my $dbh = connect_database($r);
			($res, $reason) = check_login($r, $dbh, $password);
			$dbh->disconnect();
			
			# Store the cache key for latter use
			$r->pnotes("RedmineCacheKey" => $cache_key) if $res == OK;	
		}
		
	} elsif($res == AUTH_REQUIRED) {
		my $dbh = connect_database($r);
		if(is_authentication_forced($dbh)) {
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
	
	my ($hashed_password, $status, $auth_source_id, $salt) = query_fetch_first($dbh, 'SELECT hashed_password, status, auth_source_id, salt FROM users WHERE login = ?', $user);
	
	# Not found
	return (AUTH_REQUIRED, "unknown user '$user'") unless defined($hashed_password);

	# Check password	
	if($auth_source_id) {
		# LDAP authentication
		
		# Ensure Authen::Simple::LDAP is available
		return (SERVER_ERROR, "Redmine LDAP authentication requires Authen::Simple::LDAP")
			unless $CanUseLDAPAuth;

		# Get LDAP server informations
		my($host, $port, $tls, $account, $account_password, $base_dn, $attr_login) = query_fetch_first(
			$dbh,
			"SELECT host,port,tls,account,account_password,base_dn,attr_login from auth_sources WHERE id = ?",
			$auth_source_id
		);
		
		# Check them
		return (SERVER_ERROR, "Undefined authentication source for '$user'")
			unless defined $host;

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
		my $pass_digest = Digest::SHA1::sha1_hex($password);
		return (AUTH_REQUIRED, "wrong password for '$user'")
			unless $hashed_password eq Digest::SHA1::sha1_hex($salt.$pass_digest);
	}
	
	# Password is ok, check if account if locked	
	return (FORBIDDEN, "inactive account: '$user'") unless $status eq 1;

	$r->log->debug("successfully authenticated as active redmine user '$user'");

	# Everything's ok	
	return OK;
}

# check if authentication is forced
sub is_authentication_forced {
	my $dbh = shift;
  return is_true(query_fetch_first($dbh, "SELECT value FROM settings WHERE settings.name = 'login_required'"));
}

sub authz_handler {
  my $r = shift;

  unless ($r->some_auth_required) {
      $r->log_reason("No authentication has been configured");
      return FORBIDDEN;
  }

  my $dbh = connect_database($r); 
  
  my ($identifier, $project_id, $is_public, $status) = get_project_data($r, $dbh);
	$is_public = is_true($is_public);

	my($res, $reason) = FORBIDDEN;
  
  unless(defined($project_id)) {
  	# Unknown project
  	$res = DECLINED;
  	$reason = "not a redmine project";
  	
  } elsif($status ne 1 && !defined($read_only_methods{$r->method})) {
  	# Write operation on archived project is forbidden
  	$reason = "write operations on inactive project '$identifier' are forbidden";

	} elsif(!$r->user) {
  	# Anonymous access
		$res = AUTH_REQUIRED;
		$reason = "anonymous access to '$identifier' denied";
		
		if($is_public) {
			# Check anonymous permissions
	 		my $required = required_permission($r);
			my ($id) = query_fetch_first($dbh, "SELECT id FROM roles WHERE builtin = 2 AND permissions LIKE ?", '%'.$required.'%');
			$res = OK if defined $id;
		}
  	
  	# Force login if failed
		$r->note_auth_failure unless $res == OK;
		
  } else {
  	# Logged in user
 		my $required = required_permission($r);
 		my $user = $r->user;
 		
 		# Look for membership with required role
 		my($id) = query_fetch_first($dbh, q{
			SELECT roles.id FROM users, members, member_roles, roles
			WHERE users.login = ?
			  AND users.id = members.user_id
			  AND	members.project_id = ?
			  AND members.id = member_roles.member_id
			  AND member_roles.role_id = roles.id
			  AND roles.permissions LIKE ?
		}, $user, $project_id, '%'.$required.'%');

		if(!defined($id) && $is_public) {
			# Fallback to non-member role for public projects
			$id = query_fetch_first($dbh, "SELECT id FROM roles WHERE builtin = 1 AND permissions LIKE ?", '%'.$required.'%');
		}
		
 		if(defined($id)) {
			$res = OK;
			
			my $cache_key = $r->pnotes("RedmineCacheKey");
			cache_set($r, $cache_key) if defined $cache_key;

		} else {
			$reason = "insufficient permissions (user: '$user', project: '$identifier', required: '$required')";
		}
  }

	$r->log->debug("access granted: user '", ($r->user || 'anonymous'), "', project '$identifier', method: '", $r->method, "'") if $res == OK;  

  $r->log_reason($reason) if $res != OK && defined $reason;
  
  return $res;
}

# get project identifier
sub get_project_identifier {
	my $r = shift;
	my $dbh = shift;
	
	my $location = $r->location;
  my ($identifier) = $r->uri =~ m{^\Q$location\E/*([^/]+)};
  return $identifier;
}

# get information about the project
sub get_project_data {
	my $r = shift;
	my $dbh = shift;
	
  my $identifier = get_project_identifier($r);
	return $identifier, query_fetch_first($dbh, "SELECT id, is_public, status FROM projects WHERE identifier = ?", $identifier);
}

# get redmine permission based on HTTP method
sub required_permission {
	my $r = shift;
	$read_only_methods{$r->method} || ':commit_access';
}

# return module configuration for current directory
sub get_config {
	my $r = shift;
	Apache2::Module::get_config(__PACKAGE__, $r->server, $r->per_dir_config);
}

# get a connection to the redmine database
sub connect_database {
	my $r = shift;    

	my $cfg = get_config($r);
	return DBI->connect($cfg->{RedmineDSN}, $cfg->{RedmineDbUser}, $cfg->{RedmineDbPass});
}

# execute a query and return the first row
sub query_fetch_first {
	my $dbh = shift;
	my $query = shift;

  my $sth = $dbh->prepare($query);
  $sth->execute(@_);
	my @row = $sth->fetchrow_array();
  $sth->finish();
  undef $sth;

	@row;	
}

# tell if a value returned from SQL is "true"
sub is_true {
	my $value = shift;
  return defined($value) && ($value eq "1" || $value eq 1 || $value eq "t");
}

# build credential cache key
sub get_cache_key {
	my ($r, $password) = @_;
	return Digest::SHA1::sha1_hex(join(':', get_project_identifier($r), $r->user, $password, required_permission($r)));
}

# check if credentials exist in cache
sub cache_get {
	my($r, $key) = @_;
	my $cfg = get_config($r);
	my $cache = $cfg->{RedmineCacheCreds};
	return unless $cache;
	my $time = $cache->get($key) or return 0;
	if($cfg->{RedmineCacheCredsMaxAge} && ($r->request_time - $time) > $cfg->{RedmineCacheCredsMaxAge}) {
		$cache->unset($key);
		$cfg->{RedmineCacheCredsCount}--;
		return 0;
	}
	1;
}

# put credentials in cache
sub cache_set {
	my($r, $key) = @_;
	my $cfg = get_config($r);
	my $cache = $cfg->{RedmineCacheCreds};
	return unless $cache;
	if($cfg->{RedmineCacheCredsCount} >= $cfg->{RedmineCacheCredsMax}) {
		$cache->clear;
		$cfg->{RedmineCacheCredsCount} = 0;
	}
	$cache->set($key, $r->request_time);
	$cfg->{RedmineCacheCredsCount}++;
}

1;


package RPC::Switch;

#
# Mojo's default reactor uses EV, and EV does not play nice with signals
# without some handholding. We either can try to detect EV and do the
# handholding, or try to prevent Mojo using EV.
#
#BEGIN {
#	$ENV{'MOJO_REACTOR'} = 'Mojo::Reactor::Poll';
#}
# we do the handholding now..

# mojo (from cpan)
use Mojo::Base -base;
use Mojo::File;
use Mojo::IOLoop;
use Mojo::Log;

# standard
use Carp;
use Cwd qw(realpath);
use Data::Dumper;
use Encode qw(encode_utf8 decode_utf8);
use Digest::MD5 qw(md5_base64);
use File::Basename;
use FindBin;
use List::Util qw(shuffle);
use Scalar::Util qw(refaddr);

# more cpan
use JSON::MaybeXS;

# RPC Switch aka us
use RPC::Switch::Auth;
use RPC::Switch::Channel;
use RPC::Switch::Connection;
use RPC::Switch::Server;
use RPC::Switch::WorkerMethod;

has [qw(
	apiname
	auth
	backendacl
	backendfilter
	cfg
	chunks
	clients
	connections
	daemon
	debug
	internal
	log
	methodacl
	methods
	pid_file
	ping
	servers
	timeout
	worker_id
	workers
	workermethods
)];

use constant {
	ERR_NOTNOT   => -32000, # Not a notification
	ERR_ERR	     => -32001, # Error thrown by handler
	ERR_BADSTATE => -32002, # Connection is not in the right state (i.e. not authenticated)
	ERR_NOWORKER => -32003, # No worker avaiable
	ERR_BADCHAN  => -32004, # Badly formed channel information
	ERR_NOCHAN   => -32005, # Channel does not exist
	ERR_GONE     => -32006, # Worker gone
	ERR_NONS     => -32007, # No namespace
	ERR_NOACL    => -32008, # Method matches no ACL
	ERR_NOTAL    => -32009, # Method not allowed by ACL
	ERR_BADPARAM => -32010, # No paramters for filtering (i.e. no object)
	ERR_TOOBIG   => -32010, # Req/Resp object too big
	# From http://www.jsonrpc.org/specification#error_object
	ERR_REQ	     => -32600, # The JSON sent is not a valid Request object 
	ERR_METHOD   => -32601, # The method does not exist / is not available.
	ERR_PARAMS   => -32602, # Invalid method parameter(s).
	ERR_INTERNAL => -32603, # Internal JSON-RPC error.
	ERR_PARSE    => -32700, # Invalid JSON was received by the server.
};

# keep in sync with the RPC::Switch::Client
use constant {
	RES_OK => 'RES_OK',
	RES_WAIT => 'RES_WAIT',
	RES_ERROR => 'RES_ERROR',
	RES_OTHER => 'RES_OTHER', # 'dunno'
};

sub new {
	my ($class, %args) = @_;
	my $self = $class->SUPER::new();

	my $cfgdir = $args{cfgdir};
	die "no configdir?" unless $cfgdir;
	my $cfgfile = $args{cfgfile} // 'rpcswitch.conf';
	my $cfgpath = "$cfgdir/$cfgfile";

	my $slurp = Mojo::File->new($cfgpath)->slurp();
	my $cfg;
	local $@;
	eval $slurp;
	die "failed to load config $cfgpath: $@\n" if $@;
	die "empty config $cfgpath?" unless $cfg;
	$self->{cfg} = $cfg;

	my $apiname = $self->{apiname} = ($args{apiname} || fileparse($0)); # . " [$$]";
	my $daemon = $self->{daemon} = $args{daemon} // 0; # or 1?
	my $debug = $self->{debug} = $args{debug} // 0; # or 1?

	my $log = $self->{log} = $args{log} // Mojo::Log->new(level => ($debug) ? 'debug' : 'info');
	$log->path(realpath("$FindBin::Bin/../log/$apiname.log")) if $daemon;

	my $pid_file = $cfg->{pid_file} // realpath("$FindBin::Bin/../log/$apiname.pid");
	die "$apiname already running?" if $daemon and check_pid($pid_file);

	#print Dumper($cfg);
	my $methodcfg = $cfg->{methods} or die 'no method configuration?';
	$self->{methodpath} = "$cfgdir/$methodcfg";
	$self->_load_config();
	die 'method config failed to load?' unless $self->{methods};

	# keep sorted
	$self->{chunks} = 0; # how many json chunks we handled
	$self->{clients} = {}; # connected clients
	$self->{connections} = 0; # how many connections we've had
	$self->{internal} = {}; # rpcswitch.x internal methods
	$self->{pid_file} = $pid_file if $daemon;
	$self->{ping} = $args{ping} || 60;
	$self->{timeout} = $args{timeout} // 60; # 0 is a valid timeout?
	$self->{worker_id} = 0; # global worker_id counter
	$self->{workers} = 0; # count of connected workers
	$self->{workermethods} = {}; # announced worker methods

	# announce internal methods
	$self->register('rpcswitch.announce', sub { $self->rpc_announce(@_) }, non_blocking => 1, state => 'auth');
	$self->register('rpcswitch.get_clients', sub { $self->rpc_get_clients(@_) }, state => 'auth');
	$self->register('rpcswitch.get_method_details', sub { $self->rpc_get_method_details(@_) }, state => 'auth');
	$self->register('rpcswitch.get_methods', sub { $self->rpc_get_methods(@_) }, state => 'auth');
	$self->register('rpcswitch.get_stats', sub { $self->rpc_get_stats(@_) }, state => 'auth');
	$self->register('rpcswitch.get_workers', sub { $self->rpc_get_workers(@_) }, state => 'auth');
	$self->register('rpcswitch.hello', sub { $self->rpc_hello(@_) }, non_blocking => 1);
	$self->register('rpcswitch.ping', sub { $self->rpc_ping(@_) });
	$self->register('rpcswitch.withdraw', sub { $self->rpc_withdraw(@_) }, state => 'auth');

	$self->{auth} = RPC::Switch::Auth->new(
		$cfgdir, $cfg, 'auth',
	) or die 'no auth?';

	die "no listen configuration?" unless ref $cfg->{listen} eq 'ARRAY';
	my @servers;
	for my $l (@{$cfg->{listen}}) {
		push @servers, RPC::Switch::Server->new($self, $l);
	}
	$self->{servers} = \@servers;

	return $self;
}

sub _load_config {
	my ($self) = @_;

	my $path = $self->{methodpath}
		or die 'no methodpath?';

	my $slurp = Mojo::File->new($path)->slurp();

	my ($acl, $backend2acl, $backendfilter, $method2acl, $methods);

	local $SIG{__WARN__} = sub { die @_ };

	eval $slurp;

	die "error loading method config: $@" if $@;
	die 'emtpy method config?' unless $acl && $backend2acl
		&& $backendfilter && $method2acl && $methods;

	# reverse the acl hash: create a hash of users with a hash of acls
	# these users belong to as values
	my %who2acl;
	while (my ($a, $b) = each(%$acl)) {
		#say 'processing ', $a;
		my @acls = ($a, 'public');
		my @users;
		my $i = 0;
		my @tmp = ((ref $b eq 'ARRAY') ? @$b : ($b));
		while ($_ = shift @tmp) {
			#say "doing $_";
			if (/^\+(.*)$/) {
				#say "including acl $1";
				die "acl depth exceeded for $1" if ++$i > 10;
				my $b2 = $acl->{$1};
				die "unknown acl $1" unless $b2;
				push @tmp, ((ref $b2 eq 'ARRAY') ? @$b2 : $b2);
			} else {
				push @users, $_
			}
		}
		#print 'acls: ', Dumper(\@acls);
		#print 'users: ', Dumper(\@users);
		# now we have a list of acls resolving to a list o users
		# for all users in the list of users
		for my $u (@users) {
			# add the acls
			if ($who2acl{$u}) {
				$who2acl{$u}->{$_} = 1 for @acls;
			} else {
				$who2acl{$u} = { map { $_ => 1} @acls };
			}
		}
	}

	# check if all acls mentioned exist
	while (my ($a, $b) = each(%$backend2acl)) {
		#my @tmp = ((ref $b eq 'ARRAY') ? @$b : ($b));
		$b = [ $b ] unless ref $b;
		for my $c (@$b) {
			die "acl $c unknown for backend $a" unless $acl->{$c};
		}
	}

	while (my ($a, $b) = each(%$method2acl)) {
		#my @tmp = ((ref $b eq 'ARRAY') ? @$b : ($b));
		$b = [ $b ] unless ref $b;
		for my $c (@$b) {
			die "acl $c unknown for method $a" unless $acl->{$c};
		}
	}

	# namespace magic
	my %methods;
	while (my ($namespace, $ms) = each(%$methods)) {
		while (my ($m, $md) = each(%$ms)) {
			$md = { b => $md } if not ref $md;
			my $be = $md->{b};
			die "invalid metod details for $namespace.$m: missing backend"
				unless $be;
			$md->{b} = "$be$m" if $be =~ '\.$';
			$methods{"$namespace.$m"} = $md;
		}
	}

	if ($self->{debug}) {
		my $log = $self->{log};
		$log->debug('acl           ' . Dumper($acl));
		$log->debug('backend2acl   ' . Dumper($backend2acl));
		$log->debug('backendfilter ' . Dumper($backendfilter));
		$log->debug('method2acl    ' . Dumper($method2acl));
		$log->debug('methods       ' . Dumper($methods));
		$log->debug('who2acl       ' . Dumper(\%who2acl));
	}

	$self->{backend2acl} = $backend2acl;
	$self->{backendfilter} = $backendfilter;
	$self->{method2acl} = $method2acl;
	$self->{methods} = \%methods;
	$self->{who2acl} = \%who2acl;
}

sub work {
	my ($self) = @_;
	if ($self->daemon) {
		daemonize();
	}

	if (Mojo::IOLoop->singleton->reactor->isa('Mojo::Reactor::EV')) {
		$self->log->info('Mojo::Reactor::EV detected, enabling workarounds');
		#Mojo::IOLoop->recurring(1 => sub {
		#	$self->log->debug('--tick--') if $self->{debug}
		#});
		$self->{__async_check} = EV::check(sub {
			#$self->log->debug('--tick--') if $self->{debug};
			1;
		});
	}

	local $SIG{TERM} = local $SIG{INT} = sub {
		$self->_shutdown(@_);
	};

	local $SIG{HUP} = sub {
		$self->log->info('trying to reload config');
		local $@;
		eval {
			$self->_load_config();
		};
		$self->log->error("config reload failed: $@") if $@;
	};

	$self->log->info('RPC::Switch starting work');
	Mojo::IOLoop->start unless Mojo::IOLoop->is_running;
	$self->log->info('RPC::Switch done?');

	return 0;
}

sub rpc_ping {
	my ($self, $c, $r, $i, $rpccb) = @_;
	return 'pong?';
}

sub rpc_hello {
	my ($self, $con, $r, $args, $rpccb) = @_;
	#$self->log->debug('rpc_hello: '. Dumper($args));
	my $who = $args->{who} or die "no who?";
	my $method = $args->{method} or die "no method?";
	my $token = $args->{token} or die "no token?";

	$self->auth->authenticate($method, $con, $who, $token, sub {
		my ($res, $msg, $reqauth) = @_;
		if ($res) {
			$self->log->info("hello from $who succeeded: method $method msg $msg");
			$con->who($who);
			$con->reqauth($reqauth);
			$con->state('auth');
			$rpccb->(JSON->true, "welcome to the rpcswitch $who!");
		} else {
			$self->log->info("hello failed for $who: method $method msg $msg");
			$con->state(undef);
			# close the connecion after sending the response
			Mojo::IOLoop->next_tick(sub {
				$con->close;
			});
			$rpccb->(JSON->false, 'you\'re not welcome!');
		}
	});
}

sub rpc_get_clients {
	my ($self, $con, $r, $i) = @_;

	#my $who = $con->who;
	# fixme: acl for this?
	my %clients;

	for my $c ( values %{$self->{clients}} ) {
		$clients{$c->{from}} = {
			localname => $c->{server}->{localname},
			(($c->{methods} && %{$c->{methods}}) ? (methods => [keys %{$c->{methods}}]) : ()),
			num_chan => scalar keys %{$c->{channels}},
			who => $c->{who},
			($c->{workername} ? (workername => $c->{workername}) : ()),
		}
	}

	# follow the rpc-switch calling conventions here
	return (RES_OK, \%clients);
}

sub rpc_get_method_details {
	my ($self, $con, $r, $i, $cb) = @_;

	my $who = $con->who;

	my $method = $i->{method} or die 'method required';

	my $md = $self->{methods}->{$method}
		or die "method $method not found";

	$method =~ /^([^.]+)\..*$/
		or die "no namespace in $method?";
	my $ns = $1;

	my $acl = $self->{method2acl}->{$method}
		  // $self->{method2acl}->{"$ns.*"}
		  // die "no method acl for $method";

	die "acl $acl does not allow calling of $method by $who"
		unless $self->_checkacl($acl, $con->who);

	$md = { %$md }; # copy

	# now find a backend
	my $backend = $md->{b};

	my $l = $self->{workermethods}->{$backend};

	if ($l) {
		if (ref $l eq 'HASH') {
			my $dummy;
			# filtering
			($dummy, $l) = each %$l;
		}
		if (ref $l eq 'ARRAY' and @$l) {
			my $wm = $$l[0];
			$md->{doc} = $wm->{doc}
				// 'no documentation available';
		}
	} else {
		$md->{msg} = 'no backend worker available';
	}


	# follow the rpc-switch calling conventions here
	return (RES_OK, $md);
}

sub rpc_get_methods {
	my ($self, $con, $r, $i) = @_;

	my $who = $con->who;
	my $methods = $self->{methods};
	#print 'methods: ', Dumper($methods);
	my @m;

	for my $method ( keys %$methods ) {
		$method =~ /^([^.]+)\..*$/
			or next;
		my $ns = $1;
		my $acl = $self->{method2acl}->{$method}
			  // $self->{method2acl}->{"$ns.*"}
			  // next;

		next unless $self->_checkacl($acl, $who);

		push @m, { $method => ( $methods->{$method}->{d} // 'undocumented method' ) };
	}

	# follow the rpc-switch calling conventions here
	return (RES_OK, \@m);
}

sub rpc_get_stats {
	my ($self, $con, $r, $i) = @_;

	#my $who = $con->who;
	# fixme: acl for stats?

	my $methods = $self->{methods};
	keys %$methods; #reset
	my ($k, $v, %m);
	while ( ($k, $v) = each(%$methods) ) {
		$v = $v->{'#'};
		$m{$k} = $v if $v;
	}

	my %stats = (
		chunks => $self->{chunks},
		clients => scalar keys %{$self->{clients}},
		connections => $self->{connections},
		workers => $self->{workers},
		methods => \%m,
	);

	# follow the rpc-switch calling conventions here
	return (RES_OK, \%stats);
}

sub rpc_get_workers {
	my ($self, $con, $r, $i) = @_;

	#my $who = $con->who;
	my $workermethods = $self->{workermethods};
	#print 'workermethods: ', Dumper($workermethods);
	my %workers;

	for my $l ( values %$workermethods ) {
		if (ref $l eq 'ARRAY' and @$l) {
			#print 'l : ', Dumper($l);
			for my $wm (@$l) {
				push @{$workers{$wm->connection->workername}}, $wm->method;
			}
		} elsif (ref $l eq 'HASH') {
			# filtering
			keys %$l; # reset each
			while (my ($f, $wl) = each %$l) {
				for my $wm (@$wl) {
					push @{$workers{$wm->connection->workername}}, [$wm->method, $f];
				}
			}
		}
	}

	# follow the rpc-switch calling conventions here
	return (RES_OK, \%workers);
}

# kept as a debuging reference..
sub _checkacl_slow {
	my ($self, $acl, $who) = @_;
	
	#$acl = [$acl] unless ref $acl;
	say "check if $who is in any of ('",
		(ref $acl ? join("', '", @$acl) : $acl), "')";

	my $a = $self->{who2acl}->{$who} // { public => 1 };
	say "$who is in ('", join("', '", keys %$a), "')";

	#return scalar grep(defined, @{$a}{@$acl}) if ref $acl;
	if (ref $acl) {
		my @matches = grep(defined, @{$a}{@$acl});
		print  'matches: ', Dumper(\@matches);
		return scalar @matches;
	}
	return $a->{$acl};
}

sub _checkacl {
	my $a = $_[0]->{who2acl}->{$_[2]} // { public => 1 };
	return scalar grep(defined, @{$a}{@{$_[1]}}) if ref $_[1];
	return $a->{$_[1]};
}

sub rpc_announce {
	my ($self, $con, $req, $i, $rpccb) = @_;
	my $method = $i->{method} or die 'method required';
	my $who = $con->who;
	$self->log->info("announce of $method from $who ($con->{from})");
	my $workername = $i->{workername} // $con->workername // $con->who;
	my $filter     = $i->{filter};
	my $worker_id = $con->worker_id;
	unless ($worker_id) {
		# it's a new worker: assign id
		$worker_id = ++$self->{worker_id};
		$con->worker_id($worker_id);
		$self->{workers}++; # and count
	}
	$self->log->debug("worker_id: $worker_id");

	# check if namespace.method matches a backend2acl (maybe using a namespace.* wildcard)
	# if not: fail
	# check if $client->who appears in that acl

	$method =~ /^([^.]+)\..*$/ 
		or die "no namespace in $method?";
	my $ns = $1;

	my $acl = $self->{backend2acl}->{$method}
		  // $self->{backend2acl}->{"$ns.*"}
		  // die "no backend acl for $method";

	die "acl $acl does not allow announce of $method by $who"
		unless $self->_checkacl($acl, $con->who);

	# now check for filtering

	my $filterkey = $self->{backendfilter}->{$method}
			// $self->{backendfilter}->{"$ns.*"};

	my $filtervalue;

	if ( $filterkey ) {
		$self->log->debug("looking for filterkey $filterkey");
		if ($filter) {
			die "filter should be a json object" unless ref $filter eq 'HASH';
			for (keys %$filter) {
				die "filtering is not allowed on field $_ for method $method"
					unless '' . $_ eq $filterkey;
				$filtervalue = $filter->{$_};
				die "filtering on a undefined value makes little sense"
					unless defined $filtervalue;
				die "filtering is only allowed on simple values"
					if ref $filtervalue;
				# do something here?
				#$filtervalue .= ''; # force string context?
			}
		} else {
			die "filtering is required for method $method";
		}
	} elsif ($filter) {
		die "filtering not allowed for method $method";
	}

	my $wm = RPC::Switch::WorkerMethod->new(
		method => $method,
		connection => $con,
		doc => $i->{doc},
		($filterkey ? (
			filterkey => $filterkey,
			filtervalue => $filtervalue
		) : ()),
	);

	die "already announced $wm" if $con->methods->{$method};
	$con->methods->{$method} = $wm;

	$con->workername($workername) unless $con->workername;

	if ($filterkey) {
		push @{$self->workermethods->{$method}->{$filtervalue}}, $wm
	} else {
		push @{$self->workermethods->{$method}}, $wm;
	}

	# set up a ping timer to the client after the first succesfull announce
	unless ($con->tmr) {
		$con->{tmr} = Mojo::IOLoop->recurring( $con->ping, sub { $self->_ping($con) } );
	}
	$rpccb->(JSON->true, { msg => 'success', worker_id => $worker_id });

	return;
}

sub rpc_withdraw {
	my ($self, $con, $m, $i) = @_;
	my $method = $i->{method} or die 'method required';

	my $wm = $con->methods->{$method} or die "unknown method";
	# remove this action from the clients action list
	delete $con->methods->{$method};

	if (not %{$con->methods} and $con->{tmr}) {
		# cleanup ping timer if client has no more actions
		$self->log->debug("remove tmr $con->{tmr}");
		Mojo::IOLoop->remove($con->{tmr});
		delete $con->{tmr};
		# and reduce worker count
		$self->{workers}--;
	}

	# now remove this workeraction from the listenstring workeraction list

	my $wmh = $self->{workermethods};
	my $l;
	if (my $fv = $wm->filtervalue) {
		$l = $wmh->{$method}->{$fv};
		if ($#$l) {
			my $rwm = refaddr $wm;
			splice @$l, $_, 1 for grep(refaddr $$l[$_] == $rwm, 0..$#$l);
			delete $wmh->{$method}->{$fv} unless @$l;
		} else {
			delete $wmh->{$method}->{$fv};
		}
		delete $wmh->{$method} unless
			%{$wmh->{$method}};

	} else {
		$l = $wmh->{$method};

		if ($#$l) {
			my $rwm = refaddr $wm;
			splice @$l, $_, 1 for grep(refaddr $$l[$_] == $rwm, 0..$#$l);
			delete $wmh->{$method} unless @$l;
		} else {
			delete $wmh->{$method};
		}

	}

	#print 'workermethods: ', Dumper($wmh);

	return 1;
}

sub _ping {
	my ($self, $con) = @_;
	my $tmr;
	Mojo::IOLoop->delay(sub {
		my $d = shift;
		my $e = $d->begin;
		$tmr = Mojo::IOLoop->timer(10 => sub { $e->(@_, 'timeout') } );
		$con->call('rpcswitch.ping', {}, sub { $e->($con, @_) });
	},
	sub {
		my ($d, $e, $r) = @_;
		#print  'got ', Dumper(\@_);
		if ($e and $e eq 'timeout') {
			$self->log->info('uhoh, ping timeout for ' . $con->who);
			Mojo::IOLoop->remove($con->id); # disconnect
		} else {
			if ($e) {
				$self->log->debug("'got $e->{message} ($e->{code}) from $con->{who}");
				return;
			}
			$self->log->debug('got ' . $r . ' from ' . $con->who . ' : ping(' . $con->worker_id . ')');
			Mojo::IOLoop->remove($tmr);
		}
	});
}

sub _shutdown {
	my($self, $sig) = @_;
	$self->log->info("caught sig$sig, shutting down");

	# do cleanup here

	Mojo::IOLoop->stop;
}

# register internal rpcswitch.* methods
sub register {
	my ($self, $name, $cb, %opts) = @_;
	my %defaults = ( 
		by_name => 1,
		non_blocking => 0,
		notification => 0,
		raw => 0,
		state => undef,
	);
	croak 'no self?' unless $self;
	croak 'no callback?' unless ref $cb eq 'CODE';
	%opts = (%defaults, %opts);
	croak 'a non_blocking notification is not sensible'
		if $opts{non_blocking} and $opts{notification};
	croak "internal methods need to start with rpcswitch." unless $name =~ /^rpcswitch\./;
	croak "method $name already registered" if $self->{internal}->{$name};
	$self->{internal}->{$name} = { 
		name => $name,
		cb => $cb,
		by_name => $opts{by_name},
		non_blocking => $opts{non_blocking},
		notification => $opts{notification},
		raw => $opts{raw},
		state => $opts{state},
	};
}

sub _handle_internal_request {
	my ($self, $c, $r) = @_;
	my $m = $self->{internal}->{$r->{method}};
	my $id = $r->{id};
	return $self->_error($c, $id, ERR_METHOD, 'Method not found.') unless $m;

	#$self->log->debug('	m: ' . Dumper($m));
	return $self->_error($c, $id, ERR_NOTNOT, 'Method is not a notification.') if !$id and !$m->{notification};

	return $self->_error($c, $id, ERR_REQ, 'Invalid Request: params should be array or object.')
		if ref $r->{params} ne 'ARRAY' and ref $r->{params} ne 'HASH';

	return $self->_error($c, $id, ERR_PARAMS, 'This method expects '.($m->{by_name} ? 'named' : 'positional').' params.')
		if ref $r->{params} ne ($m->{by_name} ? 'HASH' : 'ARRAY');
	
	return $self->_error($c, $id, ERR_BADSTATE, 'This method requires connection state ' . ($m->{state} // 'undef'))
		if $m->{state} and not ($c->state and $m->{state} eq $c->state);

	if ($m->{raw}) {
		my $cb;
		$cb = sub { $c->write(encode_json($_[0])) if $id } if $m->{non_blocking};

		local $@;
		#my @ret = eval { $m->{cb}->($c, $jsonr, $r, $cb)};
		my @ret = eval { $m->{cb}->($c, $r, $cb)};
		return $self->_error($c, $id, ERR_ERR, "Method threw error: $@") if $@;
		#say STDERR 'method returned: ', Dumper(\@ret);

		$c->write(encode_json($ret[0])) if !$cb and $id;
		return
	}

	my $cb;
	$cb = sub { $self->_result($c, $id, \@_) if $id; } if $m->{non_blocking};

	local $@;
	my @ret = eval { $m->{cb}->($c, $r, $r->{params}, $cb)};
	return $self->_error($c, $id, ERR_ERR, "Method threw error: $@") if $@;
	#$self->log->debug('method returned: '. Dumper(\@ret));
	
	return $self->_result($c, $id, \@ret) if !$cb and $id;
	return;
}

sub _handle_request {
	my ($self, $c, $request) = @_;
	my $debug = $self->{debug};
	$self->log->debug('    in handle_request') if $debug;
	my $method = $request->{method} or die 'huh?';
	my $id = $request->{id};

	my ($backend, $md);
	unless ($md = $self->{methods}->{$method}) {
		# try it as an internal method then
		return $self->_handle_internal_request($c, $request);
	}
	$backend = $self->{methods}->{$method}->{b};

	$self->log->debug("rpc_catchall for $method") if $debug;

	# auth only beyond this point
	return $self->_error($c, $id, ERR_BADSTATE, 'This method requires an authenticated connection')
		unless $c->{state} and 'auth' eq $c->{state};

	# check if $c->who is in the method2acl for this method?
	my ($ns) = split /\./, $method, 2;
	return $self->_error($c, $id, ERR_NONS, "no namespace in $method?")
		unless $ns;

	my $acl = $self->{method2acl}->{$method}
		  // $self->{method2acl}->{"$ns.*"}
		  // return $self->_error($c, $id, ERR_NOACL, "no method acl for $method");

	my $who = $c->{who};
	return $self->_error($c, $id, ERR_NOTAL, "acl $acl does not allow method $method for $who")
		unless $self->_checkacl($acl, $who);

	#print  'workermethods: ', Dumper($self->workermethods);

	my $l; 

	if (my $fk = $self->{backendfilter}->{$backend}
			// $self->{backendfilter}->{"$ns.*"}) {

		$self->log->debug("filtering for $backend with $fk") if $debug;
		my $p = $request->{params};
		return $self->_error($c, $id, ERR_BADPARAM, "Parameters should be a json object for filtering.")
			unless ref $p eq 'HASH';

		my $fv = $p->{$fk};

		return $self->_error($c, $id, ERR_BADPARAM, "filter parameter $fk undefined.")
			unless defined($fv);

		$l = $self->{workermethods}->{$backend}->{$fv};

		return $self->_error($c, $id, ERR_NOWORKER,
			"No worker available after filtering on $fk for backend $backend")
				unless $l and @$l;
	} else {
		$l = $self->{workermethods}->{$backend};
		return $self->_error($c, $id, ERR_NOWORKER, "No worker available for $backend.")
			unless $l and @$l;
	}

	#print  'l: ', Dumper($l);

	my $wm;
	if ($#$l) { # only do expensive calculations when we have to
		# rotate workermethods
		push @$l, shift @$l;
		# sort $l by refcount
		$wm = (sort { $a->{connection}->{refcount} <=> $b->{connection}->{refcount}} @$l)[0];
		# this should produce least refcount round robin balancing
	} else {
		$wm = $$l[0];
	}
	return $self->_error($c, $id, ERR_INTERNAL, 'Internal error.') unless $wm;

	my $wcon = $wm->{connection};
	$self->log->debug("forwarding $method to $wcon->{workername} ($wcon->{worker_id}) for $backend")
		if $debug;

	# find or create channel
	my $vci = md5_base64(refaddr($c).':'.refaddr($wcon)); # should be unique for this instance?
	my $channel;
	unless ($channel = $c->{channels}->{$vci}) {
		$channel = RPC::Switch::Channel->new(
			client => $c,
			vci => $vci,
			worker => $wcon,
			refcount => 0,
			reqs => {},
		);
		$c->channels->{$vci} =
			$wcon->channels->{$vci} =
				$channel;
	}
	if ($id) {
		$wcon->{refcount}++;
		$channel->{reqs}->{$id} = 1;
	}
	$md->{'#'}++;

	# rewrite request to add rcpswitch information
	my $workerrequest = encode_json({
		jsonrpc => '2.0',
		rpcswitch => {
			vcookie => 'eatme', # channel information version
			vci => $vci,
			who => $who,
		},
		method => $backend,
		params => $request->{params},
		id  => $id,
	});

	# forward request to worker
	if ($debug) {
		$self->log->debug("refcount connection $wcon $wcon->{refcount}");
		$self->log->debug("refcount channel $channel " . scalar keys %{$channel->reqs});
		$self->log->debug('    writing: ' . decode_utf8($workerrequest));
	}

	#$wcon->_write(encode_json($workerrequest));
	$wcon->{ns}->write($workerrequest);
	return; # exlplicit empty return
}

sub _handle_channel {
	my ($self, $c, $jsonr, $r) = @_;
	my $debug = $self->{debug};
	$self->log->debug('    in handle_channel') if $debug;
	my $rpcswitch = $r->{rpcswitch};
	my $id = $r->{id};
	
	# fixme: error on a response?
	unless ($rpcswitch->{vcookie}
			 and $rpcswitch->{vcookie} eq 'eatme'
			 and $rpcswitch->{vci}) {
		return $self->_error($c, $id, ERR_BADCHAN, 'Invalid channel information') if $r->{method};
		$self->log->info("invalid channel information from $c"); # better error message?
		return;
	}

	#print 'rpcswitch: ', Dumper($rpcswitch);
	#print 'channels; ', Dumper($self->channels);
	my $chan = $c->{channels}->{$rpcswitch->{vci}};
	my $con;
	my $dir;
	if ($chan) {
		if (refaddr($c) == refaddr($chan->{worker})) {
			# worker to client
			$con = $chan->{client};
			$dir = -1;
		} elsif (refaddr($c) == refaddr($chan->{client})) {
			# client to worker
			$con = $chan->{worker};
			$dir = 1;
		} else {
			$chan = undef;
		}
	}		
	unless ($chan) {
		return $self->_error($c, $id, ERR_NOCHAN, 'No such channel.') if $r->{method};
		$self->log->info("invalid channel from $c");
		return;
	}		
	if ($id) {
		if ($r->{method}) {
			$chan->{reqs}->{$id} = $dir;
		} else {
			$c->{refcount}--;
			delete $chan->{reqs}->{$id};
		}
	}
	if ($debug) {
		$self->log->debug("refcount connection $c $c->{refcount}");
		$self->log->debug("refcount $chan " . scalar keys %{$chan->reqs});
		$self->log->debug('    writing: ' . decode_utf8($$jsonr));
	}
	#print Dumper($chan->reqs);
	# forward request
	# we could spare a encode here if we pass the original request along?
	#$con->_write(encode_json($r));
	$con->{ns}->write($$jsonr);
	return;
}


sub _error {
	my ($self, $c, $id, $code, $message, $data) = @_;
	return $c->_error($id, $code, $message, $data);
}

sub _result {
	my ($self, $c, $id, $result) = @_;
	$result = $$result[0] if scalar(@$result) == 1;
	#$self->log->debug('_result: ' . Dumper($result));
	$c->_write(encode_json({
		jsonrpc	    => '2.0',
		id	    => $id,
		result	    => $result,
	}));
	return;
}

sub _disconnect {
	my ($self, $client) = @_;
	$self->log->info('oh my.... ' . ($client->who // 'somebody')
				. ' (' . $client->from . ') disonnected..');

	delete $self->clients->{refaddr($client)};
	return unless $client->who;

	for my $m (keys %{$client->methods}) {
		$self->log->debug("withdrawing $m");
		# hack.. fake a rpcswitch.withdraw request
		$self->rpc_withdraw($client, {method => 'withdraw'}, {method => $m});
	}

	for my $c (values %{$client->channels}) {
		#say 'contemplating ', $c;
		my $vci = $c->vci;
		my $reqs = $c->reqs;
		my ($con, $dir);
		if (refaddr $c->worker == refaddr $client) {
			# worker role in this channel: notify client 
			$con = $c->client;
			$dir = 1;
		} else {
			# notify worker
			$con = $c->worker;
			$dir = -1;
		}
		for my $id (keys %$reqs) {
			if ($reqs->{$id} == $dir) {
				$con->_error($id, ERR_GONE, 'opposite end of channel gone');
			} # else ?
		}
		$con->notify('rpcswitch.channel_gone', {channel => $vci});
		delete $con->channels->{$vci};
		#delete $self->channels->{$vci};
		$c->delete();
	}
}


1;

__END__


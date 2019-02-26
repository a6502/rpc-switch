package RPC::Switch::Auth::ClientCert;
use Mojo::Base 'RPC::Switch::Auth::Base';

#use Data::Dumper;
use Scalar::Util qw(blessed);
use List::Util qw(any);

has [qw(cnfile)];

sub new {
	my $self = shift->SUPER::new();

	my ($cfgdir, $cfg) = @_;

	my $cnfile = $cfg->{cnfile} or die "no cnfile";

	die "cnfile $cnfile does not exist" unless -r "$cfgdir/$cnfile";

	$self->{cnfile} = "$cfgdir/$cnfile";
	return $self;
}


sub authenticate {
	my ($self, $connection, $who) = @_; # ignore token

	return (0, 'undef argument(s)') unless $connection and $who;

	my $h = $connection->stream->handle;

	say 'h is a ', blessed($h);

	return (0, 'no handle?') unless $h;

	return (0, 'not a ssl connection') unless $h->isa('IO::Socket::SSL');

	my $cn = $h->peer_certificate('cn');

	return (0, 'no peer cn?') unless $cn;

	my @u;
	open my $fh, '<', $self->cnfile or return (0, 'cannot open cnfile');
	while (<$fh>) {
		chomp;
		my ($a, $b) = split /:/;
		next unless $a; # skip invalid lines
		if ($a eq $cn) {
			@u = split /,/, $b;
			last;
		}
	}
	close $fh;

	return (0, "cn $cn not found") unless @u;

	return (0, "user $who not allowed for cn $cn") unless any { $who eq $_ } @u;

        return (1, 'whoohoo');
}

1;

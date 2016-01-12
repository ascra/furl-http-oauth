package Furl::HTTP::OAuth;

use warnings;
use strict;
use URI;
use URI::Escape;
use Furl::HTTP;
use Digest::HMAC_SHA1;

# make OAuth 1.0 authorized requests with Furl
# http://tools.ietf.org/html/rfc5849

sub new {
    my $class = shift;
    my %opts = ();

    if (@_) {
        if (@_ == 1 && ref $_[0] eq 'HASH') {
            %opts = %{$_[0]};
        } else {
            %opts = @_;
        }
    }

    my $consumer_key     = delete $opts{consumer_key};
    my $consumer_secret  = delete $opts{consumer_secret};
    my $signature_method = delete $opts{signature_method};
    my $token            = delete $opts{token};
    my $token_secret     = delete $opts{token_secret};

    # nonce generator
    my $nonce = delete $opts{nonce} || sub {
        my @chars = ("A".."Z", "a".."z");
        my $str = "";
        
        $str .= $chars[int(rand(scalar(@chars)))] 
            for (1..8);
        
        return $str;
    };

    # timestamp generator
    my $timestamp = delete $opts{timestamp} || sub {
        return time();
    };

    bless {
        consumer_key => $consumer_key,
        consumer_secret => $consumer_secret,
        signature_method => $signature_method,
        token => $token,
        token_secret => $token_secret,
        nonce => $nonce,
        timestamp => $timestamp,
        furl => Furl::HTTP->new(%opts)
    }, $class;
}

sub request {
    my $self = shift;
    my %args = @_;

    # TODO: accept HTTP::Request

    my $url        = $args{url};
    my $scheme     = $args{scheme};
    my $host       = $args{host};
    my $port       = $args{port};
    my $path_query = $args{path_query};
    my $content    = $args{content};
    my $method     = $args{method};
    my $headers    = $args{headers};
    my $write_file = $args{write_file};
    my $write_code = $args{write_code};

    my $consumer_key     = $self->{consumer_key};
    my $consumer_secret  = $self->{consumer_secret};
    my $token            = $self->{token};
    my $token_secret     = $self->{token_secret};
    my $signature_method = $self->{signature_method};
    my $timestamp        = &{$self->{timestamp}};
    my $nonce            = &{$self->{nonce}};
    my $uri              = undef;

    # parse url
    if ($url) {
        $uri = URI->new($url);
    } else {
        $uri = URI->new;
        $uri->scheme($scheme);
        $uri->host($host);
        $uri->port($port);
        $uri->path_query($path_query);
    }
    
    # build signature
    my $signature = "";
    my @query_form = $uri->query_form;

    if ($signature_method eq 'HMAC-SHA1') {
        # build signature base string

        # method part
        my $base_string = uc($method) . '&';

        # url part
        # exclude ports 80 and 443
        my $port = $uri->port;
        $port = $port && ($port == 443 || $port == 80) ? '' : (':' . $port);
        $base_string .= _encode(
            lc($uri->scheme . '://' . $uri->authority . $port . $uri->path)
        ) . '&';
        
        # normalize parameters
        my @sorted_params = ();
        my %params = ();

        # TODO: bring in params from application/x-www-form-urlencoded body parts 

        # for the sake of sorting, construct a param mapping
        for (my $i = 0; $i <= (@query_form - 1); $i += 2) {
            my $k = _encode($query_form[$i]);
            my $v = _encode($query_form[$i + 1]);

            if (exists $params{$k}) {
                push @{$params{$k}}, $v;
            } else {
                $params{$k} = [ $v ];
            }
        }

        # add oauth parameters
        $params{oauth_consumer_key}     = [ _encode($consumer_key) ];
        $params{oauth_token}            = [ _encode($token) ];
        $params{oauth_signature_method} = [ _encode($signature_method) ];
        $params{oauth_timestamp}        = [ _encode($timestamp) ];
        $params{oauth_nonce}            = [ _encode($nonce) ];

        # sort params and join each key/value with a '='
        foreach my $key (sort keys %params) {
            my $vals = $params{$key};

            # we have to sort the values in case of duplicate params (see RFC)
            push @sorted_params, $key . '=' . $_
                for (sort @$vals);
        }

        # add sorted encoded params
        $base_string .= _encode(join('&', @sorted_params));

        # compute digest
        my $key = _encode($consumer_secret) . '&' . _encode($token_secret);
        my $hmac = Digest::HMAC_SHA1->new($key);
        $hmac->add($base_string);
        $signature = $hmac->b64digest;

        # pad signature
        # https://metacpan.org/pod/Digest::SHA#PADDING-OF-BASE64-DIGESTS
        $signature .= '=' while (length($signature) % 4);
    } elsif ($signature_method eq 'PLAINTEXT') {
        # TODO
    } else {
        die "Invalid signature method $signature_method";
    }

    push @query_form, (
        oauth_consumer_key => $consumer_key,
        oauth_nonce => $nonce,
        oauth_signature_method => $signature_method,
        oauth_timestamp => $timestamp,
        oauth_token => $token,
        oauth_signature => $signature
    );

    $uri->query_form(\@query_form);

    return $self->{furl}->request(
        method => $method,
        url => $uri->as_string,
        content => $content,
        headers => $headers,
        write_file => $write_file,
        write_code => $write_code
    );
}

sub get {
    my ($self, $url, $headers) = @_;

    return $self->request(
        method => 'GET',
        url => $url,
        headers => $headers
    );
}

sub head {
    my ($self, $url, $headers) = @_;

    return $self->request(
        method => 'HEAD',
        url => $url,
        headers => $headers
    );
}

sub post {
    my ($self, $url, $headers, $content) = @_;

    return $self->request(
        method => 'POST',
        url => $url,
        headers => $headers,
        content => $content
    );
}

sub put {
    my ($self, $url, $headers, $content) = @_;

    return $self->request(
        method => 'PUT',
        url => $url,
        headers => $headers,
        content => $content
    );
}

sub delete {
    my ($self, $url, $headers) = @_;

    return $self->request(
        method => 'DELETE',
        url => $url,
        headers => $headers
    );
}

sub _encode {
    return URI::Escape::uri_escape(shift, '^\w.~-');
}

1;

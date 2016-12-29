package Catalyst::Authentication::Credential::Auth0::Oauth2;

use Moo;
use WebService::Auth0;
use JSON::MaybeXS;

our $VERSION = '0.001';

has [qw/client_secret client_id domain/] => (is=>'ro', required=>1);

has _redirect_uri => (
  is=>'ro',
  init_arg=>'redirect_uri',
  predicate=>'has_redirect_uri');

has auth0 => (
  is=>'bare',
  lazy=>1,
  required=>1,
  builder=>'_build_auth0',
  handles=>[qw/get_token_from_authorization_code
    get_userinfo_from_access_token/],
);

  sub _build_auth0 {
    return WebService::Auth0->new(
      client_id => $_[0]->client_id,
      client_secret => $_[0]->client_secret,
      domain => $_[0]->domain,
    );
  }

sub redirect_uri {
  my ($self, $c, $params) = @_;
  return ($params||+{})->{redirect_uri} if exists(($params||+{})->{redirect_uri});
  return $self->_redirect_uri if $self->has_redirect_uri;
  my $redirect_uri = $c->req->uri->clone;
  $redirect_uri->query(undef);
  return $redirect_uri;
}

sub BUILDARGS {
  my ($self, $config, $ctx, $realm) = @_;
  return $config;
}

sub authenticate {
  my ($self, $c, $realm, $params) = @_;
  if(my $code = $c->req->query_parameters->{code}) {    
    my $auth_res = $self->get_token_from_authorization_code(
      code => $code,
      redirect_uri => $self->redirect_uri($c, $params),
    );

    my $auth_data = decode_json($auth_res->{content});

    use Devel::Dwarn;
    Dwarn $auth_data;

    my $userinfo_res = $self->get_userinfo_from_access_token(
      $auth_data->{access_token});

    use Devel::Dwarn;
    Dwarn $userinfo_res;

    my $userinfo_data = decode_json($userinfo_res->{content});

    use Devel::Dwarn;
    Dwarn $userinfo_data;
    
    my $user = $realm->find_user($userinfo_data, $c);
    $c->log->warn("Did not find user in realm $realm") if $c->debug & !$user;

    return $user;
  }  

  $c->log->warn("Attempt to authenticate without a code") if $c->debug;
  return;
}

1;

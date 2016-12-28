package Catalyst::Authentication::Credential::Auth0::Oauth2;

use Moo;
use HTTP::Tiny;
use Devel::Dwarn;

our $VERSION = '0.001';

has domain => (
  is=>'ro',
  required=>1);

has client_id => (
  is=>'ro',
  required=>1);

has client_secret => (
  is=>'ro',
  required=>1);

has redirect_uri => (is=>'ro');

has authorization_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/authorize"});

has token_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/oauth/token"});

has user_info_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/userinfo"});

has api_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/api"});

has ua => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {HTTP::Tiny->new});

sub BUILDARGS {
  my ($self, $config, $ctx, $realm) = @_;
  return $config;
}

sub authenticate {
  my ($self, $ctx, $realm, $auth_info) = @_;
  if(my $code = $ctx->req->query_parameters->{code}) {
    (my $redirect_uri = $self->redirect_uri ||
      $ctx->req->uri->clone)->query(undef);
    
    my $res = $self->ua->post_form(
      $self->token_url, [
        client_id => $self->client_id,
        client_secret => $self->client_secret,
        grant_type => 'authorization_code',
        code => $code,
        redirect_uri => $redirect_uri,
      ]);

    Dwarn $res;        
  }
  return @_;
}

1;

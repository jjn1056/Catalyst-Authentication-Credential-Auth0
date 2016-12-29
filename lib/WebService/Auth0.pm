package WebService::Auth0;

use Moo;
use HTTP::Tiny;

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

has ua => (
  is=>'bare',
  handles=>[qw/post_form get/],
  lazy=>1,
  required=>1,
  default=>sub { HTTP::Tiny->new });

has userinfo_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/userinfo"});

has token_url => (
  is=>'ro',
  lazy=>1,
  required=>1,
  default=>sub {"https://${\$_[0]->domain}/oauth/token"});


sub get_token_from_authorization_code {
  my ($self, %params) = @_;
  die "'code' is a required parameter" unless $params{code};
  my $res = $self->post_form(
    $self->token_url, [
      client_id => $self->client_id,
      client_secret => $self->client_secret,
      grant_type => 'authorization_code',
      %params,
    ]);

  return $res;
}

sub get_userinfo_from_access_token {
  my ($self, $access_token) = @_;
  my $res = $self->get(
    $self->userinfo_url,
    { headers => {Authorization => "Bearer $access_token"} },
  );
  return $res;
}


=head1 NAME

WebService::Auth0- Prototype for Auth0.com API

=head1 SYNOPSIS

    use WebService::Auth0;
    my $auth0 = WebService::Auth0->new(
      domain => 'my-domain',
      client_id => 'my-client_id',
      client_secret => 'my-client_secrete');

    $auth0->...

=head1 DESCRIPTION

Prototype for a web service client for L<https://auth0.com>.  This is probably
going to change a lot as I learn how it actually works.  I wrote this
primarily as I was doing L<Catalyst::Authentication::Credential::Auth0>
since it seemed silly to stick web service client stuff directly into
the Catalyst authorization credential class.  Hopefully this will
eventually evolve into a true stand alone distribution.  If you use this
directly please be aware I reserve the right to change it from release
to release as needed.

=head1 METHODS

This class defines the following methods:

=head2 get_token_from_authorization_code

=head1 SEE ALSO
 
L<Catalyst::Authentication::Credential::Auth0>, L<https://auth0.com>.

=head1 AUTHOR
 
    John Napiorkowski L<email:jjnapiork@cpan.org>
  
=head1 COPYRIGHT & LICENSE
 
Copyright 2016, John Napiorkowski L<email:jjnapiork@cpan.org>
 
This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

1;

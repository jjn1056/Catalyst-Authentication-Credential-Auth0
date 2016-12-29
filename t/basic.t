use Test::Most;

{
  package MyApp::Controller::Root;
  use base 'Catalyst::Controller';

  sub auth0_cb :Path(/auth0/callback) {
    my ($self, $c) = @_;
    my $return_to = $c->req->query_parameters->{return_to};
    $c->authenticate({
      redirect_uri=>$c->uri_for($c->action, {return_to=>$return_to}),
    });
    $c->res->redirect($return_to); $c->detach;
  }

  sub protected :Local Args(0) {
    my ($self, $c) = @_;
    $c->detach('login') unless $c->user_exists;
    use Data::Dumper;
    $c->res->body('You got access!:'. Dumper($c->user));
  }

  sub login :Local Args(0) {
    my ($self, $c) = @_;
    $c->res->body(qq[
      <html>
        <head>
          <title>Needs Login!</title>
          <script src="https://cdn.auth0.com/js/lock/10.6/lock.min.js"></script>
          <script>
            var lock = new Auth0Lock('$ENV{AUTH0_CLIENT_ID}', '$ENV{AUTH0_DOMAIN}', {
              auth: {
                redirectUrl: '${\$c->uri_for($self->action_for('auth0_cb'), {return_to=>${\$c->req->uri}})}',
                responseType: 'code',
                params: {
                  scope: 'openid email' // Learn about scopes: https://auth0.com/docs/scopes
                }
              }
            });
          </script>
        </head>
        <body>
          <button onclick="lock.show();">Login</button>
        </body>
      </html>
      ]);
  }

  $INC{'MyApp/Controller/Root.pm'} = __FILE__;

  package MyApp;

  use Catalyst::Authentication::Store::Null;
  sub Catalyst::Authentication::Store::Null::for_session {
    my ( $self, $c, $user ) = @_;
    warn "111" x 1000;
    my %flat = %{$user};

    # Removed all the keys that are objects since the
    # cookie store doesn't want to deal with it.
    delete $flat{email_verified};
    delete $flat{is_verified};
    delete $flat{installed};
    delete $flat{verified};
    delete $flat{identities};

    use Devel::Dwarn; Dwarn \%flat;
    return \%flat;
  }

  sub Catalyst::Authentication::Store::Null::from_session {
    my ( $self, $c, $user ) = @_;
    return bless $user, 'Catalyst::Authentication::User::Hash';
  }

 
  use Catalyst qw/
    Session
    Session::State::Cookie
    Session::Store::Cookie
    Authentication/;

  MyApp->config(
    'Plugin::Session' => {storage_secret_key => 'abc123'},
    'Plugin::Authentication' => {
      default => {
        credential => {
          class => 'Auth0::Oauth2',
          domain => $ENV{AUTH0_DOMAIN},
          client_id => $ENV{AUTH0_CLIENT_ID},
          client_secret => $ENV{AUTH0_CLIENT_SECRET},
        },
        store => {
          class => 'Null',
        },
      },
    },
    'Controller::Root' => { namespace => '' },
  );

  MyApp->setup;
}

use Test::WWW::Mechanize::Catalyst qw/MyApp/;

ok my $m = Test::WWW::Mechanize::Catalyst->new;
 
$m->get_ok("http://localhost/protected", 'opened page');
$m->content_contains("Needs Login!", "not logged in...");

done_testing;

MyApp->to_app;

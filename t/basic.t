use Test::Most;

{
  package MyApp::Controller::Root;
  use base 'Catalyst::Controller';

  sub auth0_cb :Path(/auth0/callback) {
    my ($self, $c) = @_;
    my $return_to = $c->req->query_parameters->{return_to};
    my $redirect_uri = $c->uri_for($c->action, {return_to=>$return_to});
    $c->authenticate({redirect_uri=>$redirect_uri});
    $c->res->redirect($return_to); 
  }

  sub protected :Local Args(0) {
    my ($self, $c) = @_;
    $c->detach('login') unless $c->user_exists;
    $c->res->body("You got access ${\$c->user->{name}}!"); 
  }

  sub login :Local Args(0) {
    my ($self, $c) = @_;
    $c->res->body(qq[
      <html>
        <head>
          <title>Needs Login!</title>
          <script src="https://cdn.auth0.com/js/lock/10.6/lock.min.js"></script>
        </head>
        <body>
          <div id="root" style="
            width: 320px; 
            margin: 40px auto; 
            padding: 10px; 
            border-style: dashed; 
            border-width: 1px; 
            box-sizing: 
            border-box;">
              embedded area
          </div>
          <script>
            var lock = new Auth0Lock('$ENV{AUTH0_CLIENT_ID}', '$ENV{AUTH0_DOMAIN}', {
              container: 'root',
              auth: {
                redirectUrl: '${\$c->uri_for($self->action_for('auth0_cb'), {return_to=>${\$c->req->uri}})}',
                responseType: 'code',
                params: {
                  scope: 'openid email' // Learn about scopes: https://auth0.com/docs/scopes
                }
              }
            });
            lock.show();
          </script>
        </body>
      </html>
    ]);
  }

  $INC{'MyApp/Controller/Root.pm'} = __FILE__;

  package MyApp;

  use Catalyst qw/
    Session
    Session::State::Cookie
    Session::Store::Dummy
    Authentication/;

  MyApp->config(
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

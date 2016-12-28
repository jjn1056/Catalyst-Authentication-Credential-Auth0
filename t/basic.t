use Test::Most;

{
  package MyApp::Controller::Root;
  use base 'Catalyst::Controller';

  sub protected :Local Args(0) {
    my ($self, $c) = @_;
    $c->detach('login') unless $c->authenticate(111);
    $c->res->body('You got access!');
  }

  sub login :Local Args(0) {
    my ($self, $c) = @_;
    $c->res->body(qq[
      <html>
        <head>
          <title>Hi</title>
          <script src="https://cdn.auth0.com/js/lock/10.6/lock.min.js"></script>
          <script>
            var lock = new Auth0Lock('$ENV{AUTH0_CLIENT_ID}', 'jjn1056.auth0.com', {
              auth: {
               // redirectUrl: 'https://YOUR_APP/callback',
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
  
  use Catalyst 'Authentication';

  MyApp->config(
    'Plugin::Authentication' => {
      default => {
        credential => {
          class => 'Auth0::Oauth2',
          domain => 'jjn1056.auth0.com',
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

use Catalyst::Test 'MyApp';

{
  ok my ($res, $c) = ctx_request( '/protected' );
  is $res->code, 200;
}

done_testing;

MyApp->to_app;

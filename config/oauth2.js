var oauth2orize             = require('oauth2orize'),
    promisify               = require('bluebird').promisify,
    trustedClientPolicy     = require('../api/policies/isTrustedClient.js');
    passport                = require('passport');
    
// Create OAuth 2.0 server
var server = oauth2orize.createServer();
    
/**
 * Exchange user id and password for access tokens.
 *
 * The callback accepts the `client`, which is exchanging the user's name and password
 * from the token request for verification. If these values are validated, the
 * application issues an access token on behalf of the user who authorized the code.
 */
var exchangePasswordHandler = function (client, username, password, scope, next) {
  if (!client) return next(null, false); //passport-oauth2-client-password needs to be configured
  //Validate the user
  Users.authenticate(username, password).then(function (user) {
    if (!user) return next(null, false);
    return Tokens.generateToken({
      client_id: client.client_id,
      user_id: user.id
    }).then(function (token) {
      return next(null, token.access_token, token.refresh_token, {
        expires_in: token.calc_expires_in()
      })
    });
  });
};

/**
 * Exchange the refresh token for an access token.
 *
 * The callback accepts the `client`, which is exchanging the client's id from the token
 * request for verification.  If this value is validated, the application issues an access
 * token on behalf of the client who authorized the code
 */
var exchangeRefreshTokenHandler = function (client, refreshToken, scope, done) {
  API.Model(Tokens).findOne({
    refresh_token: refreshToken
  }).then(function (token) {
    if (!token) return done(null, null);
    return Tokens.generateToken({
      user_id: token.user_id,
      client_id: token.client_id
    }).then(function (token) {
      return done(null, token.access_token, token.refresh_token, {
        expires_in: token.calc_expires_in()
      });

    });
  }).catch(function (err) {
    done(err);
  });
};

var init = function () {
    server.exchange(oauth2orize.exchange.password(exchangePasswordHandler));
    server.exchange(oauth2orize.exchange.refreshToken(exchangeRefreshTokenHandler));
}

//OAuth Token Services
var sendToken = function (req, res) {
    var validateAndSendToken    = promisify(server.token());
    var tokenErrorMessage       = server.errorHandler();
    if (req && req.method != 'POST') throw 'Unsupported method';
    return validateAndSendToken(req, res).catch(function (err) {
        tokenErrorMessage(err, req, res);
    });
};

var tokenInfo = function (data, context) {
    var token = context.authorization.token;
    token.expires_in = token.calc_expires_in();
    return {
        identity: context.identity,
        authorization: context.authorization
    };
}

module.exports = {
 http: {
    customMiddleware: function (app) {
      // Initialize passport
      app.use(passport.initialize());
      app.use(passport.session());
      init();

      /***** OAuth authorize endPoints *****/

    //   app.get('/oauth/authorize',
    //     login.ensureLoggedIn(),
    //     server.authorize(function(clientId, redirectURI, done) {

    //       Client.findOne({clientId: clientId}, function(err, client) {
    //         if (err) { return done(err); }
    //         if (!client) { return done(null, false); }
    //         if (client.redirectURI != redirectURI) { return done(null, false); }
    //         return done(null, client, client.redirectURI);
    //       });
    //     }),
    //     server.errorHandler(),
    //     function(req, res) {
    //       res.render('dialog', { transactionID: req.oauth2.transactionID,
    //                              user: req.user,
    //                              client: req.oauth2.client 
    //       });
    //     }
    //   );

    //   app.post('/login', passport.authenticate('local', { successReturnToOrRedirect: '/', failureRedirect: '/login' }));

    //   app.post('/oauth/authorize/decision',
    //     login.ensureLoggedIn(), 
    //     server.decision());

      /***** OAuth token endPoint *****/

      app.post('/oauth/token',
        trustedClientPolicy,
        passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
        sendToken
      );
    }
 }
}; 
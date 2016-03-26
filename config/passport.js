/**
 * Module dependencies.
 */
var passport = require('passport');
var PublicClientPasswordStrategy = require('passport-oauth2-public-client').Strategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var BasicStrategy = require('passport-http').BasicStrategy;

//Handlers

/**
 * Public Client strategy
 *
 * The OAuth 2.0 public client authentication strategy authenticates clients
 * using a client ID. The strategy requires a verify callback,
 * which accepts those credentials and calls done providing a client.
 */
var publicClientVerifyHandler = function (clientId, next) {
  process.nextTick(function () {
    API.Model(Clients).findOne({client_id: clientId}).nodeify(next);
  });
};

/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens.  The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate.  Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).  While this approach is not recommended by
 * the specification, in practice it is quite common.
 */

var clientPasswordHandler = function (clientId, clientSecret, next) {
  process.nextTick(function () {
    API.Model(Clients).findOne({client_id: clientId}).nodeify(next);
  });
};

var basicHandler = function (username, password, next) {
  process.nextTick(function () {
    API.Model(Users).findOne({username: username}).nodeify(next);
  });
};

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate either users or clients based on an access token
 * (aka a bearer token).  If a user, they must have previously authorized a client
 * application, which is issued an access token to make requests on behalf of
 * the authorizing user.
 */
var bearerVerifyHandler = function (token, next) {
  process.nextTick(function () {
    Tokens.authenticate({access_token: token}).nodeify(function (err, info) {
      if (!info || !info.identity) return next(null, null);
      next(null, info.identity, info.authorization);
    });
  });
};

//Initialize Passport Strategies
passport.use(new PublicClientPasswordStrategy(publicClientVerifyHandler));
passport.use(new ClientPasswordStrategy(clientPasswordHandler));
passport.use(new BearerStrategy(bearerVerifyHandler));
passport.use(new BasicStrategy(basicHandler));
var oauth2orize = require('oauth2orize'),
    promisify = require('bluebird').promisify,
    login = require('connect-ensure-login'),
    passport = require('passport'),
    trustedClientPolicy = require('../api/policies/isTrustedClient.js');

// Create OAuth 2.0 server
var server = oauth2orize.createServer();

// Obtaining the user's authorization involves multiple request/response pairs. 
// During this time, an OAuth 2.0 transaction will be serialized to the session. 
// Client serialization functions are registered to customize this process, 
// which will typically be as simple as serializing the client ID, 
// and finding the client by ID when deserializing.
server.serializeClient(function(client, done) {
    return done(null, client.id);
});

server.deserializeClient(function(id, done) {
    API.Model(Tokens).findOne({
        client_id: id
    }).nodeify(function(err, client) {
        if (err) { return done(err); }
        return done(null, client);
    });
});

// Generate authorization code
server.grant(oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    API.Model(AuthCodes).create({
        client_id: client.clientId,
        redirect_uri: redirectURI,
        user_id: user.id,
        scope: ares.scope
    }).nodeify(function(err, authCode) {
        if (err) { return done(err, null); }
        return done(null, authCode.code);
    });
}));

// Exchange authorization code for access token
server.exchange(oauth2orize.exchange.code(function(client, code, redirectURI, done) {
    API.Model(AuthCodes).findOne({
        code: code
    }).nodeify(function(err, authCode) {
        if (err || !authCode) {
            return done(err);
        }
        if (client.client_id !== code.client_id) {
            return done(null, false);
        }
        if (redirectURI !== code.redirect_uri) {
            return done(null, false);
        }

        // Remove Refresh and Access tokens and create new ones
        API.Model(Tokens).destroy({
            user_id: code.user_id,
            client_id: code.client_id
        }).nodeify(function(err) {
            if (err) {
                return done(err);
            } else {
                API.Model(Tokens).destroy({
                    user_id: code.user_id,
                    client_id: code.client_id
                }).nodeify(function(err) {
                    if (err) {
                        return done(err);
                    } else {
                        Tokens.generateToken({
                            user_id: code.user_id,
                            client_id: code.client_id
                        }).nodeify(function(err, token) {
                            if (err) {
                                return done(err);
                            } else {
                                return done(null, token.access_token, token.refresh_token, {
                                    expires_in: token.calc_expires_in()
                                });
                            }
                        });
                    }
                });
            }
        });
    });
}));

/**
 * Exchange user id and password for access tokens.
 *
 * The callback accepts the `client`, which is exchanging the user's name and password
 * from the token request for verification. If these values are validated, the
 * application issues an access token on behalf of the user who authorized the code.
 */
var exchangePasswordHandler = function(client, username, password, scope, next) {
    if (!client) return next(null, false); //passport-oauth2-client-password needs to be configured
    //Validate the user
    Users.authenticate(username, password).then(function(user) {
        if (!user) return next(null, false);
        return Tokens.generateToken({
            client_id: client.client_id,
            user_id: user.id
        }).then(function(token) {
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
var exchangeRefreshTokenHandler = function(client, refreshToken, scope, done) {
    API.Model(Tokens).findOne({
        refresh_token: refreshToken
    }).then(function(token) {
        if (!token) return done(null, null);
        return Tokens.generateToken({
            user_id: token.user_id,
            client_id: token.client_id
        }).then(function(token) {
            return done(null, token.access_token, token.refresh_token, {
                expires_in: token.calc_expires_in()
            });
        });
    }).catch(function(err) {
        done(err);
    });
};

// Authenticate Authorization Code Grant
var authCodeAuthenticate = function(clientId, redirectURI, done) {
    API.Model(Clients).findOne({
        client_id: clientId
    }).nodeify(function(err, client) {
        if (err) { return done(err); }
        if (!client) { return done(null, false); }
        if (client.redirect_uri != redirectURI) { return done(null, false); }
        return done(null, client, client.redirect_uri);
    });
};

var renderDialog = function(req, res) {
    res.render('dialog', {
        transactionID: req.oauth2.transactionID,
        user: req.user,
        client: req.oauth2.client
    });
}

var init = function() {
    server.exchange(oauth2orize.exchange.password(exchangePasswordHandler));
    server.exchange(oauth2orize.exchange.refreshToken(exchangeRefreshTokenHandler));
}

//OAuth Token Services
var sendToken = function(req, res) {
    var validateAndSendToken = promisify(server.token());
    var tokenErrorMessage = server.errorHandler();
    if (req && req.method != 'POST') throw 'Unsupported method';
    return validateAndSendToken(req, res).catch(function(err) {
        tokenErrorMessage(err, req, res);
    });
};

var tokenInfo = function(data, context) {
    var token = context.authorization.token;
    token.expires_in = token.calc_expires_in();
    return {
        identity: context.identity,
        authorization: context.authorization
    };
}

module.exports = {
    http: {
        customMiddleware: function(app) {
            // Initialize passport
            app.use(passport.initialize());
            app.use(passport.session());
            init();

            /***** OAuth authorize endPoints *****/
            app.get('/oauth/authorize',
                login.ensureLoggedIn(),
                server.authorize(authCodeAuthenticate),
                server.errorHandler()
            );

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
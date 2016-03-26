module.exports = function (req, res, next) {
  OAuth.authenticator.authenticate(['basic', 'oauth2-client-password'], {session: false});
};
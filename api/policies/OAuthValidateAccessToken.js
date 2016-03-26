var passport = require('passport');
module.exports = function (req, res, next) {
  passport.authenticate('bearer', {session: false}, function (err, identity, authorization) {
    if (!identity) return res.send(401);

    req.identity = identity;
    req.authorization = authorization;

    next();
  })(req, res);
};
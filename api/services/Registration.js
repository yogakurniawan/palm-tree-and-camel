var Promise = require('bluebird'),
    promisify = Promise.promisify,
    mailer = require('nodemailer'),
    validator = require("email-validator");

var Module = {
    transporter: mailer.createTransport({
        service: 'gmail',
        auth: {
            user: sails.config.security.admin.email.address,
            pass: sails.config.security.admin.email.password
        }
    }),
    emailGeneratedCode: function(options) {
        var url = options.verifyURL,
            that = Module;
        email = options.email;
        message = 'Hello!';
        message += '<br/>';
        message += 'Please visit the verification link to complete the registration process.';
        message += '<br/><br/>';
        message += 'Account with ' + options.type + " : " + options.id;
        message += '<br/><br/>';
        message += '<a href="';
        message += url;
        message += '">Verification Link</a>';
        message += '<br/>';

        that.transporter.sendMail({
            from: sails.config.security.admin.email.address,
            to: email,
            subject: 'Canadian Tire App Account Registration',
            html: message
        }, function(err, info) {
            console.log("Email Response:", info);
        });
        return {
            url: url
        }
    },
    verifyClientEmailExist: function(email) {
        return API.Model(Clients).findOne({
            email: email
        });
    },
    generateClient: function(data) {
        return API.Model(Clients).create({
            client_id: Tokens.generateTokenString(),
            client_secret: Tokens.generateTokenString(),
            email: data.email
        })
    },
    generateClientToken: function(context, client) {
        context.id = client.client_id;
        context.type = 'Client ID';

        return Tokens.generateToken({
            client_id: client.client_id
        });
    },
    generateClientEmail: function(data, context, token) {
        var that = Module;
        return that.emailGeneratedCode({
            id: context.id,
            type: context.type,
            verifyURL: sails.config.security.server.url + "/clients/verify/" + data.email + "?code=" + token.code,
            email: data.email
        });
    },
    registerClient: function(data, context, req, res, client) {
        var that = Module;
        if (client) {
            return {
                error: "server_error",
                error_description: "client email already registered"
            };
        } else {
            return that.generateClient(data)
                .then(that.generateClientToken.bind(null, context))
                .then(that.generateClientEmail.bind(null, data, context));
        }
    },
    registerUser: function(data) {
        if (validator.validate(data.email)) {
            var date = new Date();
            return API.Model(Users).create({
                username: data.username,
                email: data.email,
                password: data.password,
                date_registered: date
            });
        } else {
            return Promise.reject("invalid email");
        }        
    },
    generateUserToken: function(context, user) {
        context.id = user.username;
        context.type = 'Username';
        return Tokens.generateToken({
            user_id: user.id,
            client_id: Tokens.generateTokenString()
        });
    },
    generateUserEmail: function(context, data, token) {
        return Module.emailGeneratedCode({
            id: context.id,
            type: context.type,
            verifyURL: sails.config.security.server.url + "/users/verify/" + data.email + "?code=" + token.code,
            email: data.email
        });
    },
    verifyUser: function(data) {
        return Tokens.authenticate({
            code: data.code,
            type: 'verification',
            email: data.email
        })
    },
    updateUserInfo: function(info) {
        var date = new Date();
        var criteria = {
            username: info.identity.username
        };
        var attributes = {
            date_verified: date
        };
        if (!info) return Promise.reject('Unauthorized');
        API.Model(Users).update(criteria, attributes);
        return {
            verified: true,
            email: info.identity.email
        }
    },
    verifyClient: function(data) {
        return Tokens.authenticate({
            type: 'verification',
            code: data.code,
            email: data.email
        });
    },
    updateClientInfo: function(info) {
        var date = new Date();
        var criteria = {
            client_id: info.identity.client_id
        };
        var attributes = {
            date_verified: date
        }
        if (!info) return Promise.reject('Unauthorized');
        API.Model(Clients).update(criteria, attributes);
        return {
            verified: true,
            email: info.identity.email
        };
    }
};

module.exports = {
    emailGeneratedCode: Module.emailGeneratedCode,
    currentUser: function(data, context) {
        return context.identity;
    },
    registerUser: function(data, context) {
        return Module.registerUser(data)
            .then(Module.generateUserToken.bind(null, context))
            .then(Module.generateUserEmail.bind(null, context, data));
    },
    verifyUser: function(data, context) {
        return Module.verifyUser(data)
            .then(Module.updateUserInfo);
    },
    registerClient: function(data, context, req, res) {
        var registerClient = Module.registerClient.bind(null, data, context, req, res);
        if (validator.validate(data.email)) {
            return Module.verifyClientEmailExist(data.email)
                   .then(registerClient);
        } else {
            return Promise.reject("invalid email");
        }        
    },
    verifyClient: function(data, context) {
        return Module.verifyClient(data)
            .then(Module.updateClientInfo);
    }
};
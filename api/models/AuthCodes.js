/**
 * AuthCode.js
 *
 * @description :: TODO: You might write a short summary of how this model works and what it represents here.
 * @docs        :: http://sailsjs.org/#!documentation/models
 */

var bcrypt = require('bcrypt-nodejs');
module.exports = {
    attributes: {
        code: {
            type: 'string'
        },
        user_id: {
            type: 'string',
            required: true
        },
        client_id: {
            type: 'string',
            required: true
        },
        redirect_uri: {
            type: 'string',
            required: true
        }
    },
    beforeCreate: function(authCode, next) {
        if (client.hasOwnProperty('code')) {
            authCode.code = bcrypt.hashSync(authCode.code, bcrypt.genSaltSync(16));
            next(false, authCode);
        } else {
            next(null, authCode);
        }
    }
};


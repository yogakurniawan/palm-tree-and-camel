/**
 * UsersController
 *
 * @description :: Server-side logic for managing users
 * @help        :: See http://sailsjs.org/#!/documentation/concepts/Controllers
 */

module.exports = {
  register: function (req, res) {
    API(Registration.registerUser, req, res);
  },
  'verify/:email': function (req, res) {
    API(Registration.verifyUser, req, res);
  },
  current: function (req, res) {
    API(Registration.currentUser, req, res);
  }
};


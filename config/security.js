module.exports.security = {
  oauth: {
    version: '2.0',
    token: {
      length: 32,
      expiration: 3600
    }
  },
  admin: {
    email: {
      address: 'yogaygk@gmail.com',
      password: 'Save4@ring'
    }
  },
  server: {
    url: process.env.HOST_URL || 'http://localhost:1336'
  }
};
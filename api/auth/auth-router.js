// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const bcrypt = require('bcryptjs');

const router = require("express").Router();

const { checkUsernameFree,checkUsernameExists,checkPasswordLength} = require('./auth-middleware')
const Users = require('../users/users-model')
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
  router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
    try {
        const hash = bcrypt.hashSync(req.user.password, 8);
        const user = await Users.add({ username: req.user.username, password: hash });
        res.status(201).json({
          user_id: user.user_id,
          username: user.username,
        });
    } catch(err) {
        next({message: err.message});
    }
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.post("/login",  checkUsernameExists, (req, res, next) => {
    if(bcrypt.compareSync(req.user.password, req.user.hash)) {
        req.session.user = {
            username: req.user.username,
            password: req.user.hash,
        };
        res.status(200).json(`Welcome ${req.user.username}`);
    } else {
        next({  status: 400, message: 'invalid  credentials' });
    }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res, next) => {
    if(req.session.user) {
       
        
        req.session.destroy(err => {
            if(err) {
                next({ message: 'error while logging out' });
            } else {
                res.json(`logged out`);
            }
        })
    } else {
        res.json('no session');
    }
});
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
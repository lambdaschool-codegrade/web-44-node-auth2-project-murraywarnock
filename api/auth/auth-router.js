const router = require("express").Router();
const bcrypt = require('bcryptjs');
const {
  add,
  find,
  findBy,
  findById,
} = require('../users/users-model');
const { 
  checkUsernameExists, 
  validateRoleName 
} = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { username, password, role_name } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const user = { username, password: hash, role_name };
    const newUser = await add(user);
    res.status(201).json({ 
      user_id: newUser.user_id,
      username: newUser.username,
     });
  } catch (error) {
    next(error);
  }
  
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    try {
    
    } catch (error) {
      next(error);
    }
});

module.exports = router;

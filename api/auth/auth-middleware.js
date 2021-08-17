const { JWT_SECRET } = require("../secrets/index"); // use this secret!
const jwt = require('jsonwebtoken')
const { findBy } = require('../users/users-model');


const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    const token = req.headers.authorization;

    if (token) {
      // async function
      jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
          next({ status: 401, message: "Token invalid" });
        } else {
          req.decodedJwt = decoded;
          next();
        }
      }); // old style node async callback, error first
    } else {
      next({ status: 401, message: "Token required" });
    }
};

const only = (role) => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
  if (req.decodedJwt.role_name === role) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" })
  }
};
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const user = await findBy({ username: username }); 
    if (user.length) {
      req.user = user[0];
      next();
    } else {
      next({ 
        status: 401, 
        message: "Invalid credentials" 
      });
    }
  } catch (err) {
    next(err);
  }
}

const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
//  req.body.role_name = req.body.role_name.trim();
if (req.body.role_name) {
  req.body.role_name = req.body.role_name.trim();
} else {
  req.body.role_name = "student"; 
}
const { role_name } = req.body;

 if (!role_name || role_name === '') {
  req.body.role_name = "student";
 } else  if (role_name.length > 32) {
     next({ status: 422, message: "Role name can not be longer than 32 chars"});
   } else if (role_name === "admin") {
    next({ status: 422, message: "Role name can not be admin"});
  }
 next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};

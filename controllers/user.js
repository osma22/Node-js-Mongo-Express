const User = require("../models/user");
const sendemail = require("../models/email");
const crypto = require('crypto');
const jwt = require("jsonwebtoken");


exports.signup = async (req, res)=>{     

    const {email} = req.body;     
    const userExist = await User.findOne({email});
    
     if (userExist){
      return res.status(403).json(
        {
          success: false,
          message: "E-mail already exists"
        }
      )
     }

    try {
        const user = await User.create(req.body); 
        res.status(201).json({
            success: true,
            user
        })
        
    } catch (error) {
        return res.status(500).json(
          /*{
            success: false,
            message: "Server Error"
          }*/
         console.log(error)
        )
        
    }
   
}

exports.signin = async (req, res)=>{

  try{

    //1st check
    const {email, password} = req.body;   //email & password comes from request body

  if(!email || !password){                //blank e-mail or password
    return res.status(400).json(
      {
        success: false,
        message: "Both email & password required"
      }
    )
  }
    //2nd check
     const user= await User.findOne({email});     //findone-> from mongodb database  //as we use async so it will wait some time
     if(!user){                                 // cannot find email in database
      return res.status(400).json(
        {
          success: false,
          message: "wrong email"
        }
      )
    }
      //3rd check
    const isMatched= await user.comparePassword (password);
    if(!isMatched){                                 // cannot match the password
      return res.status(400).json(
        {
          success: false,
          message: "wrong password"
        }
      )
    }

    generateToken(user, 200, res);  
 }
  catch(error){
    return res.status(400).json(
      {
        success: false,
        message: "cannot login"
      }
    )
}
}

const generateToken = async (user, statusCode, res) => {
  const token= await user.jwrtoken (); // generate a token and send it to client
  const refresh_token= await user.refreshtoken(); // generate a refresh token and send it to client

//create options for cookie
  const options = {
    httpOnly: true,
  };
  res
    .status(statusCode)
    .cookie('refreshtoken', refresh_token, options) //send token to client as a cookie   //name of cookie is 'token' and value is token
    .cookie('token', token, options) //send token to client as a cookie   //name of cookie
    .json({ success: true, token, refresh_token });

}



exports.signout = async (req, res) => {

  res.clearCookie('refreshtoken');
  res.clearCookie('token');
  res.status(200).json({
    success: true,
    message: 'Signed out successfully'
  });

};

exports.forgetpassword = async (req, res, next)=>{

    const userExist = await User.findOne({email: req.body.email});
    
     if (!userExist){
      return res.status(400).json(
        {
          success: false,
          message: "E-mail does not  exists"
        }
      )
      
     }

     //generate a random token

    const resetToken = userExist.getResetPasswordToken(); 
    await userExist.save({ validateBeforeSave: false });  //we don't want the validation   
                                                                                        
    const resetURL = `${req.protocol}://${req.get('host')}/api/user/resetpassword/${resetToken}`;  // //resetToken-> sent as a route parameter

    const message = "click the following link to reset your password: \n\n" + resetURL;
    

    //send the token to user via email
    // here we are using sendemail function which we created in models/email.js file
    // it takes email, subject and message as parameters and sends the email.
     try{
      await sendemail(
        {email: userExist.email,
        subject: "Reset Password",
        message: message}
       );

       res.status(200).json(
        {
          success: true,
          message: "Reset password link sent to your email"
        }
      )
    }
     catch(error){
      userExist.resetPasswordToken = undefined;
      userExist.resetPasswordExpires = undefined;
      await userExist.save({ validateBeforeSave: false });
     return (new ErrorResponse('Failed to send email', 500))
     }
  
}

exports.resetpassword = async (req, res)=>{
  const token = crypto.createHash('sha256').update(req.params.token).digest('hex'); //encrypted the plaintext token
  const userExist = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } }); //find user by token and check if token is valid and not expired
 // console.log(userExist);
  console.log(token);
  if (!userExist){
    return res.status(400).json(
      {
        success: false,
        message: "Invalid token or expired token"
      }
    )

    //return  (new ErrorResponse('Invalid token or expired token', 400)) 
  }


  //reset the password and save it in the database 
  userExist.password = req.body.password;
  userExist.confirmPassword = req.body.confirmPassword;
  userExist.resetPasswordToken = undefined;
  userExist.resetPasswordExpires = undefined;
  userExist.passwordChangedAt = Date.now();
  await userExist.save();  //save the user in database

  const logintoken= await userExist.jwrtoken ();


//auto login after password reset
res.status(200).json(
  {
    success: true,
    logintoken   
  }
)

}
exports.token = async (req, res) => {
  const refreshToken = req.cookies.refreshtoken;
  if (!refreshToken) {
    return res.status(403).json({ message: "Refresh token not provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, 'osmanganimehidy2');
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    generateToken(user, 200, res);  

    res.clearCookie('refreshtoken');


  
  }
   
   catch (err) {
    console.log(err);
    res.status(403).json({ message: "Invalid refresh token" });
  }
};

const express = require("express");
const app = express(); // creating server using express
const cors = require("cors");
require("dotenv").config();
const morgan = require("morgan"); //logging middleware for express
let mongoose = require("mongoose");
bodyParser = require("body-parser");
const crypto = require("crypto");
const passport = require("passport"); //passport is a middleware for authentication
app.use(express.json());
app.use(express.urlencoded({ extended: false })); //for handling POST request
app.use(bodyParser.urlencoded({ extended: true })); //for handling POST request

app.use(cors());
//passport middleware
app.use(                                
  require("express-session")({
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
  })
);

app.set("view engine", "ejs");
const User = require("./models/user");
const sendemail = require("./models/email");
//import Routes
const userRoutes = require("./routes/user"); //all prorerties of router are now in userRoutes

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection URL
const url = "mongodb://localhost:27017/user";
let db;

// Connect to MongoDB
mongoose.connect(
  url,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => {
    console.log("Connected to MongoDB");
  }
);

//middleware

app.use(express.json()); //bodyparser middleware->post and put request parsing
app.use(morgan("tiny")); //logging middleware

//routes middleware
app.use("/api", userRoutes);

const port = process.env.port || 5000;

app.listen(port, () => {
  console.log(`App is running on port ${port}`);
});

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/signup", function (req, res) {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  try {
    const user = await new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
    });
    await user.save();
    res.status(201).send("user regestered successfully");
  } catch (err) {
    res.status(500).send("Error to regestered");
  }
});

app.get("/signin", function (req, res) {
  res.render("signin");
});

app.post("/signin", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).send("User not found");
    }
    const isMatch = await user.comparePassword(req.body.password);
    if (!isMatch) {
      return res.status(400).send("wrong password");
    }
    req.session.user = { // save user info in session
      id: user._id,
      email: user.email
    };
    res.redirect("/signout");
   // res.status(200).send("Logged in successfully");
  } catch (err) {
    res.status(500).send("Log in failed");
  }
});

app.get("/signout", function (req, res) {
  res.render("signout");
});

app.post("/signout", async (req, res) =>{
  if (!req.session.user) {
    return res.status(403).json({
      success: false,
      message: 'You are not logged in',
    });
  }

  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Failed to sign out'
      });
    }
       res.clearCookie('connect.sid'); 

    res.redirect("/");

   /* res.status(200).json({
      success: true,
      message: 'Signed out successfully'
    });*/ 
  });
})


app.get("/forgetpassword", function (req, res) {
  res.render("forgetpassword");
});

app.post("/forgetpassword", async (req, res) => {
  const userExist = await User.findOne({ email: req.body.email });

  if (!userExist) {
    return res.status(400).json({
      success: false,
      message: "E-mail does not  exists",
    });
  }
  const resetToken = userExist.getResetPasswordToken();
  await userExist.save({ validateBeforeSave: false }); //we don't want the validation

  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/resetpassword/${resetToken}`; // //resetToken-> sent as a route parameter

  const message =
    "click the following link to reset your password: \n\n" + resetURL;

  try {
    await sendemail({
      email: userExist.email,
      subject: "Reset Password",
      message: message,
    });

    res.status(200).json({
      success: true,
      message: "Reset password link sent to your email",
    });
  } catch (error) {
    userExist.resetPasswordToken = undefined;
    userExist.resetPasswordExpires = undefined;
    await userExist.save({ validateBeforeSave: false });
    return new ErrorResponse("Failed to send email", 500);
  }
});

app.get("/resetpassword/:token", function (req, res) {
  res.render("resetpassword", { token: req.params.token });
});

app.post("/resetpassword/:token", async (req, res) => {
  try {
    const token = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex"); //encrypted the plaintext token
    const userExist = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    }); //find user by token and check if token is valid and not expired
    if (!userExist) {
      return res.status(400).json({
        success: false,
        message: "Invalid token or expired token",
      });
    }

    //reset the password and save it in the database
    userExist.password = req.body.password;
    userExist.resetPasswordToken = undefined;
    userExist.resetPasswordExpires = undefined;
    userExist.passwordChangedAt = Date.now();
    await userExist.save(); //save the user in database
    res.status(201).send("Password updated successfully");

  } catch (err) {
    console.error(err); // Log the error for debugging
    res.status(500).send("Password update failed");
  }
});

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const crypto = require("crypto");
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: [true, "Please add a Name"],
      maxlength: 32,
    },

    email: {
      type: String,
      trim: true,
      required: [true, "Please add a E-mail"],
      unique: true,
    },

    password: {
      type: String,
      trim: true,
      required: [true, "Please add a Password"],
      minlength: [6, "password must have at least six(6) characters"],
     /* match: [
        /^(?=.*\d)(?=.*[@#\-_$%^&+=§!\?])(?=.*[a-z])(?=.*[A-Z])[0-9A-Za-z@#\-_$%^&+=§!\?]+$/,
        "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number and a special characters",
      ],*/
    },

    token: {
      type: String,
      required: true,
      default: jwt.sign({}, process.env.SECRET, { expiresIn: 600000 }), //token expires in 10min
    },

    refreshToken: {
      type: String,
      required: true,
      default: jwt.sign({}, process.env.REFRESHSECRET, { expiresIn: 600000 }), //token expires in 10min
    },

    resetPasswordToken: String,
    resetPasswordExpires: Date,
    passwordChangedAt: Date,
  },
  { timestamps: true }
); //timestamps will add createdAt and updatedAt fields automatically

//encrypting password  => .pre-> encrypt before save

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  }
});

//verify password by a mathod

userSchema.methods.comparePassword = async function (mypassword) {
  //its an asynchronous method so it returns a promise & we have to wait to reaolve the promise-> async, await
  return bcrypt.compare(mypassword, this.password);
};

//create method for generate token  -> securely send data between two partners
userSchema.methods.jwrtoken = function () {
  return jwt.sign({ id: this.id }, process.env.SECRET, { expiresIn: 36000 }); //expires in 1hr
};

userSchema.methods.refreshtoken = function () {
  return jwt.sign({ id: this.id }, process.env.REFRESHSECRET, { expiresIn: '1y' }); //expires in 1hr
};

//create method for generate reset password token

userSchema.methods.getResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(20).toString("hex"); //generate random token
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex"); // encrypted the plaintext token for security
  this.resetPasswordExpires = Date.now() + 60000000000;
  return resetToken;
};

module.exports = mongoose.model("User", userSchema); // export the User model so we can use it in controller

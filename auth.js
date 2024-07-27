const passport = require('passport');
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const User = require("./models/user");

 
passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.googleOauthRedirectUrl,
    passReqToCallback   : true
  },
  async (request, token, refreshToken, profile, done) => {
    try {
      const user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = new User({
          googleId: profile.id,
          email: profile.email,
          displayName: profile.displayName,
          token: token,
          refreshToken: refreshToken
        
        });
        await user.save();
      } else {
        // Update the accessToken and refreshToken if user already exists
        user.token = token;
        user.refreshToken = refreshToken;
        await user.save();
      }
      return done(null, user);
    } catch (err) {
      return done(err, false);
    }
  }));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
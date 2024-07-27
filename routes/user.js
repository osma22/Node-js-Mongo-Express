const express = require('express');
const { signup, signin, signout, forgetpassword, resetpassword, token} = require('../controllers/user');

const router = express.Router();

router.post('/signup', signup);
router.post('/signin', signin);
router.post('/signout', signout);
router.post('/forgetpassword', forgetpassword);
router.patch('/resetpassword/:token', resetpassword);
router.post('/token', token);


module.exports = router;  // //everything is now in router

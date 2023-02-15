const router = require("express").Router();
const User= require('../models/User.model');
const bcrypt = require('bcryptjs');

/* GET home page */
router.get("/", (req, res, next) => {
  console.log(req.session.currentUser)
  res.render("index");
});

router.get("/signin", (req, res, next) => {
  res.render('auth/signin');
})

router.post('/signin', async (req, res, next) => {
  const { username, password } = req.body
  try {
    if (!username || !password) {
      return res.render('auth/signin', {
        errorMessage: 'Please fill out all of the fields!',
      })
    }
    const foundUser = await User.findOne({ username: username })
    if (foundUser) {
      return res.render('auth/signin', {
        errorMessage: 'Theres another one of you!',
      })
    }
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(req.body.password, salt);
    const user= {
      username: req.body.username,
      password: encryptedPassword
    }
    await User.create(user)
    res.redirect("/login");
  } catch (error) {
    next(error);
  }
})

router.get("/login", (req, res, next) => {
  res.render('auth/login');
})

router.post('/login', async (req, res, next) => {
  try {
    const {username, password}= req.body;
    if (!username || !password) {
      return res.render('auth/login', {
        errorMessage: 'Please fill out all of the fields!',
      })
    }
    const user= await User.findOne({username: username})
    if (!user) {
      return res.render('auth/login', {
        errorMessage: 'Please sign up first!',
      })
    }
    const pass= await bcrypt.compare(password, user.password);
    if(pass){
      req.session.currentUser =user;
      res.redirect('/');
    }
  } catch (error) {
    next(error)
  }
})

router.get('/logout', (req, res, next) => {
  req.session.destroy((error) => {
    if (error) {
      return next(error)
    }
    res.redirect('/login')
  })
})

router.get('/main', async (req, res, next) => {
  if(!req.session.currentUser){
    res.redirect('/');
  }else {
    res.render('main');
  }
})

router.get('/private', (req, res, next) => {
  if(!req.session.currentUser){
    res.render('index');
  }else {
    res.render('private')
  }
})

module.exports = router;

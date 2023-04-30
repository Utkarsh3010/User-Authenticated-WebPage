require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
    secret: "Our secret",
    resave: true,
    saveUninitialized: true,
    cookie: { }
}));


app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1/userDB",{useNewUrlParser:true});
//mongoose.set("useCreateIndex",true);
const userSchema = new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User',userSchema);

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  User.find({"secret":{$ne:null}}, function(err,founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        res.render("secrets",{userWithSecrets:founduser});
      }
    }
  });
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
  User.findById(req.user.id,function(err,founduser){
    if(err){
      console.log(err);
    }else{
      if(founduser){
        founduser.secret=submittedSecret;
        founduser.save();
        res.redirect("/secrets");
      }
    }
  })
});

app.get("/logout", function(req,res){
        req.logout((err)=>{
            if(err){
                console.log(err);
            }else{
                res.redirect("/");
            }
        });
});

app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});



// --------------new app.post for mongoose v-7--------------
// .post((req, res) => {
//     const newUser = new User({
//         username: req.body.username,
//         password: req.body.password
//     })
//     newUser.save().then(function(registerUser){
//         if(registerUser){
//             passport.authenticate('local')(req,res,function(){
//                 res.render('secrets');
//             })
//         }})
// });

// --------------new app.post for mongoose v-7--------------
// app.post("/register", async (req, res) => {
//
//   const newUser = new User({ username: req.body.username });
//   await newUser.setPassword(req.body.password);
//   await newUser.save();
//   await User.authenticate("local")(req.body.username, req.body.password);
//
//   res.render("secrets");
// });
app.post("/login",function(req,res){
  const user=new User({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function(){

  console.log("Server started on port 3000.");

});

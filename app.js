//jshint esversion:6
require('dotenv').config()
const express=require("express");
const ejs=require("ejs");
const mongoose=require("mongoose");
const passport=require("passport");
const session=require("express-session");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy=require('passport-facebook').Strategy;
//******************* Bcrypt *****************
// const bcrypt=require("bcrypt");
// const saltRounds=10;


// //HASH
// const md5=require("md5");

//Weak Cipher method
//const encrypt=require("mongoose-encryption");
const app=express();

app.use(express.urlencoded({extended:true}));
app.set('view engine','ejs');
app.use(express.static('public'));

app.use(session({
    secret:"peanut",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGODB_URI);

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//********************************  mongoose encryption  ****************************
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User=new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

  passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne : null}},function(err,foundUsers){
        if(err)
            console.log(err);
        else
        {
            if(foundUsers)
                res.render("secrets",{usersWithSecrets: foundUsers});
        }

    })
});

app.get("/submit",function(req,res){
    if(req.isAuthenticated())
        res.render("submit");
    else
        res.redirect("/login");
});

app.post("/submit", function (req, res) {
    const secretKey = req.body.secret;
    
    console.log(req.user); 
    const id = req.user.id;                             //////////////passport very handly saves the users details into the request variable whenever they login
   
    User.findById(id, function (err, foundUser) {
      if (err){
        console.log(err);
      } else {
        if (foundUser){
          foundUser.secret = secretKey;
          foundUser.save(function () {
            res.redirect("/secrets");
          });
        }
      }
    });
  });



app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get("/logout", function(req, res){
    req.logout(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/");
        }
    });
    
});

app.post("/register",function(req,res){
    

    User.register({username:req.body.username}, req.body.password, function(err, user) {
        if (err) 
        {
            console.log(err);
            res.redirect("/register");
        }
        else
        {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
        }
      });






    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //     const u1=new User({
    //         email: req.body.username,
    //         password:hash
    //     });
    //     u1.save(function(err){
    //         if(!err)
    //             res.render("secrets");
    //         else
    //             console.log(err);
    //     })
    // });
    
    
});

app.post("/login",function(req,res){



    const user = new User({
        username: req.body.username,
        password: req.body.password
       });
       req.login(user,function(err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req,res,function () {
                res.redirect('/secrets');
        });
        }
       });







    // const username=req.body.username;
    // const password=req.body.password;
    // User.findOne({email:username},function(err,found){
    //     if(err)
    //         console.log(err);
    //     else
    //     {
    //         if(found){
    //             bcrypt.compare(password, found.password, function(err, result) {
    //                 if(result===true)
    //                     res.render("secrets");
    //             });
    //         }
    //     }
    // });
});

app.listen(process.env.PORT||3000,function(){
    console.log("Server started on port 3000");
})
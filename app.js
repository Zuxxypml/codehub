//Creating Prerequisites
require("dotenv").config();
const { default: mongoose } = require("mongoose");
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();
// Config
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.secret_key,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
const PORT = process.env.PORT || 8080;
// MongoDB
async function main() {
  await mongoose.connect(process.env.mongo_cloud);
}
main()
  .then(() => {
    console.log("Database Connected");
  })
  .catch((e) => {
    console.log("Unable to connect to Database" + e);
  });
// Schemas
const UsersSchemas = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  githubId: String,
});
UsersSchemas.plugin(passportLocalMongoose);
UsersSchemas.plugin(findOrCreate);

const User = new mongoose.model("User", UsersSchemas);
passport.use(User.createStrategy());
// used to serialize the user for the session
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
// used to deserialize the user
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.google_client_id,
      clientSecret: process.env.google_client_secret,
      callbackURL: "http://localhost:8080/auth/google/codehub",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          googleId: profile.id,
          username: profile.displayName,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);
// Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.facebook_app_id,
      clientSecret: process.env.facebook_app_secret,
      callbackURL: "http://localhost:8080/auth/facebook/codehub",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        {
          facebookId: profile.id,
          username: profile.displayName,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);
// Github Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.github_client_id,
      clientSecret: process.env.github_client_secret,
      callbackURL: "http://localhost:8080/auth/github/codehub",
    },
    function (accessToken, refreshToken, profile, done) {
      User.findOrCreate(
        {
          githubId: profile.id,
          username: profile.username,
        },
        function (err, user) {
          return done(err, user);
        }
      );
    }
  )
);
//Get requests
app.route("/").get((req, res) => {
  res.render("home");
});
// Register
app
  .route("/register")
  .get((req, res) => {
    res.render("signup", { wrongPass: "", userExists: "" });
  })
  .post(
    (req, res, next) => {
      const username = req.body.username;
      const email = req.body.email;
      const password = req.body.pass;
      const rePassword = req.body.re_pass;
      function comparePassword() {
        if (password !== rePassword) {
          res.render("signup", {
            wrongPass: "Password do not Match :(",
            userExists: "",
          });
        } else {
          if (password === rePassword) {
            registerUser();
          }
        }
      }
      function registerUser() {
        User.register(
          { username: username, email: email },
          password,
          function (err, user) {
            if (err) {
              return res.render("signup", { wrongPass: "", userExists: "" });
            }

            // go to the next middleware
            next();
          }
        );
      }
      comparePassword();
    },
    passport.authenticate("local", {
      successRedirect: "/codehub",
      failureRedirect: "/login",
    })
  );
// Login
app
  .route("/login")
  .get((req, res) => {
    res.render("signin", { wrongPass: "" });
  })
  .post((req, res, next) => {
    passport.authenticate("local", function (err, user, info) {
      if (err) {
        return next(err);
      }
      if (!user) {
        // *** Display message without using flash option
        // re-render the login form with a message
        return res.render("signin", {
          wrongPass: "Invalid username or password",
        });
      }
      req.logIn(user, function (err) {
        if (err) {
          return next(err);
        }
        return res.redirect("/codehub");
      });
    })(req, res, next);
  });
// Homepage
app.route("/codehub").get((req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user.id, (err, found) => {
      if (err) {
        console.log(err);
      } else {
        // console.log(found);
        if (found) {
          // console.log(found);
          res.render("codehub", { username: found.username });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});
// Logout
app.route("/logout").get((req, res) => {
  req.logOut();
  res.redirect("/login");
});
// Google Auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/codehub",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/codehub");
  }
);
// Facebook Auth
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/codehub",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/codehub");
  }
);
// Github Auth
app.get("/auth/github", passport.authenticate("github"));

app.get(
  "/auth/github/codehub",
  passport.authenticate("github", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/codehub");
  }
);
// Source Code upload Page
app.route("/source").get((req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user.id, (err, found) => {
      if (err) {
        console.log(err);
      } else {
        // console.log(found);
        if (found) {
          // console.log(found);
          res.render("source", {
            username: found.username,
          });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});
// Projects page
app.route("/projects").get((req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user.id, (err, found) => {
      if (err) {
        console.log(err);
      } else {
        // console.log(found);
        if (found) {
          // console.log(found);
          res.render("projects", { username: found.username });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});
// Integration page
app.route("/integration").get((req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user.id, (err, found) => {
      if (err) {
        console.log(err);
      } else {
        // console.log(found);
        if (found) {
          // console.log(found);
          res.render("integration", { username: found.username });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});
// Setting Page
app.route("/setting").get((req, res) => {
  if (req.isAuthenticated()) {
    User.findById(req.user.id, (err, found) => {
      if (err) {
        console.log(err);
      } else {
        // console.log(found);
        if (found) {
          // console.log(found);
          res.render("setting", {
            username: found.username,
            passDoNotMatch: "",
          });
        }
      }
    });
  } else {
    res.redirect("/login");
  }
});
app
  .route("/resetusername")
  .get()
  .post((req, res) => {
    if (req.isAuthenticated()) {
      User.findById(req.user.id, (err, found) => {
        if (!err) {
          if (found) {
            found.username = req.body.username;
            found.save(() => {
              res.render("setting", {
                username: found.username,
                passDoNotMatch: "",
              });
            });
          }
        }
      });
    } else {
      res.redirect("/login");
    }
  });
// Reset password
app
  .route("/resetpassword")
  .get()
  .post((req, res) => {
    if (req.isAuthenticated()) {
      User.findById(req.user.id, (err, found) => {
        if (!err) {
          if (found) {
            function checkPass() {
              if (req.body.newpassword !== req.body.re_newpass) {
                res.render("setting", {
                  username: found.username,
                  passDoNotMatch: "Passwords Does not Match",
                });
              } else {
                if (req.body.newpassword === req.body.re_newpass) {
                  found.changePassword(
                    req.body.oldpassword,
                    req.body.newpassword,
                    (err) => {
                      if (err) {
                        console.log(err);
                      } else {
                        res.redirect("/login");
                      }
                    }
                  );
                }
              }
            }
            checkPass();
          }
        }
      });
    } else {
      res.redirect("/login");
    }
  });

// const multer = require("multer");
// const upload = multer({ dest: "./public/data/uploads/" });
// app.post("/stats", upload.any(), function (req, res) {
//   // req.file is the name of your file in the form above, here 'uploaded_file'
//   // req.body will hold the text fields, if there were any
//   console.log(req.file, req.body);
// });
//Listener
app.listen(PORT, () => {
  console.log("Server started on port 8080");
});

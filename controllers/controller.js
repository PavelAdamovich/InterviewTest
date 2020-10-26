// Models
UserModel = require("../models/user")

// User Login
Passport = require("passport")
LocalStrategy = require('passport-local').Strategy

var DAYS2MS = 24 * 60 * 60 * 1000

module.exports = {
    configure: function(app) {
        app.use(require('express-session')({
            secret: 'Massive Secret Test',
            resave: false,
            saveUninitialized: false
        }))
        app.use(Passport.initialize())
        app.use(Passport.session())
        Passport.use(new LocalStrategy(UserModel.authenticate()))
        Passport.serializeUser(UserModel.serializeUser())
        Passport.deserializeUser(UserModel.deserializeUser())
    },
    homepage: function(req, res) {
    	res.send("Homepage <a href=\"/logout\">Logout</a>")
    },
    getLoginView: function(req, res) {
    	res.render("login", {
    		errorMessage: ""
    	})
    },
    login: function(req, res) {
    	var username = req.body.username
        var email = req.body.email
        var password = req.body.password
        var rememberMe = req.body.rememberMe

        if (password === undefined || typeof password != "string" || password.length == 0) {
            res.render("login", {
            	errorMessage: "Password not provided"
            })
            return
        }

        var usernameNull = false
        var emailNull = false

        if ((username === undefined || typeof username != "string" || username.length == 0)) {
            usernameNull = true
        }

        if (email === undefined || typeof email != "string" || email.length == 0) {
            emailNull = true
        } else {
            email = email.toLowerCase()
        }

        if (usernameNull == true && emailNull == true) {
            res.render("login", {
            	errorMessage: "Username or email not provided"
            })
            return
        } else if (usernameNull == true && emailNull == false) {
            username = email
            req.body.username = email
        }

        Passport.authenticate('local', function(err, user, info) {
            if (err) {
                console.log("-- Error authenticating user in login: %O", err)
                res.send("Error: " + err)
                return
            }
            if (!user) {
                res.render("login", {
                	errorMessage: "Incorrect Login"
                })
                return
            }
            req.logIn(user, function(err) {
                if (err) {
                    console.log("-- Error req.login user in login: %O", err)
                    return
                }
                if (rememberMe) {
                    // Allow the user to be remembered by the server. When they close the browser and end their session they should not have to login again once they attempt to go to the homepage
                    req.session.cookie.maxAge = 7 * DAYS2MS // 7 days
                } else {
                    // Do not remember the user
                    req.session.cookie.expires = false
                }
                return res.redirect('/')
            })
        })(req, res)
    },
    getSignupView: function(req, res) {
    	res.render("signup", {
    		errorMessage: ""
    	})
    },
    signup: function(req, res) {
    	var username = req.body.username
        var password = req.body.password
        var confirmPassword = req.body.confirm_password
        var email = req.body.email
        var rememberMe = req.body.rememberMe

        if (username === undefined || typeof username != 'string' || username.length == 0) {
        	res.render("signup", {
                errorMessage: "Username not provided"
            })

            return
        }

        if (username.length < 6) {
            res.render("signup", {
                errorMessage: "Username should be at least 6 characters long"
            })

            return
        }

        if (password === undefined || typeof password != "string" || password.length == 0) {
        	res.render("signup", {
                errorMessage: "Password not provided"
            })

            return
        }

        var numberRegex = /\d+/

        if (password.length < 8 || password.toLocaleLowerCase() === password || !numberRegex.test(password)) {
            res.render("signup", {
                errorMessage: "Invalid password"
            })
            return
        }

        if (password !== confirmPassword) {
            res.render("signup", {
                errorMessage: "Passwords do not match" 
            })

            return
        }

        if (email === undefined || typeof email != "string" || email.length == 0) {
        	res.render("signup", {
                errorMessage: "Email not provided"
            })
            
            return
        }

        UserModel.findOne({
            $or: [{ username }, { email }]
            // Search query should be looking for a user with the provided username or a user with the provided email
        }, function(err, foundUser) {
            if (err) {
            	console.log("Error finding userModel in signup: %O", err)
            } else if (foundUser) {
            	res.render("signup", {
            		errorMessage: "Username or email has been already taken by another user."
            	})
            } else {
                UserModel.register(new UserModel({
                    username: username,
                    email: email.toLowerCase()
                }), password, function(err, user) {
                    if (err) {
                    	res.send("Error creating user")
                    	console.log("Error creating user: %O", err)
                        return
                    }
                    Passport.authenticate('local')(req, res, function() {
                        if (rememberMe) {
                            // Allow the user to be remembered by the server. When they close the browser and end their session they should not have to login again once they attempt to go to the homepage
                            req.session.cookie.maxAge = 7 * DAYS2MS // 7 days
                        } else {
                            // Do not remember the user
                            req.session.expires = false
                        }
                        res.redirect('/')
                    })
                })
            }
        })
    },
    isLoggedIn: function(req, res, next) {
        if (req.user) {
            return next()
        }
    	// Add a check to see if the user is logged in. If the user is logged in. Call next(), otherwize, redirect them to the login page
        res.redirect("/login")
    },
    logout: function(req, res) {
        req.logout()
        res.redirect("/login")
    }
}

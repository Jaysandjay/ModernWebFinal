const express = require("express")
const app = express()
const path = require("path")
const mongoose = require('mongoose')
const PORT = process.env.PORT || 3000
const bcrypt = require('bcryptjs')
const session = require('express-session')
const {check, validationResult} = require('express-validator')
require('dotenv').config()

//const CONNECTION_STRING = `mongodb+srv://dbUser:dbUser@cluster0.b9heor7.mongodb.net/?appName=Cluster0`

let Movie = require('./models/movie')
let User = require('./models/user');

app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))
app.use(express.static(path.join(__dirname, "public")))

app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 

app.use(session({
    secret: "JABOCLLA", //any random secret secure string
    resave: false,
    saveUninitialized: false,
    cookie: {},
}))

// Make logged-in user available in all templates
app.use((req, res, next) => {
    res.locals.user = req.session.loggedInUser || null;
    next();
});


const ensureLogin = (req, res, next) => {
    if (!req.session.loggedInUser){
        console.log(`no logged in user.`);
        res.redirect('/login')
    }else{
        next();
    }
}

//TBD Middleware for edit/delete with known user
const ensureUserIsOwner = async (req, res, next) => {
    try {
        const movieId = req.params.id;
        const movie = await Movie.findById(movieId);

        if (!movie) {
            return res.status(404).send("Movie not found");
        }

        if (!req.session.loggedInUser) {
            return res.redirect("/login");
        }

        // Compare movie.user with logged-in user
        if (movie.user.toString() !== req.session.loggedInUser._id.toString()) {
            return res.redirect('/movielist?error=You are not allowed to edit or delete this movie.');
        }

        // Store movie to reuse in route
        req.movie = movie;

        next();
    } catch (err) {
        console.log(err);
        return res.status(500).send("Server error");
    }
};




app.get("/", ensureLogin, (req,res) => {
    return res.render('home.ejs')
})

app.get("/register", (req, res) => {
  res.render("register");
})

app.get("/insert", (req,res) => {
  return res.render("insert.ejs")
})

app.post("/register", async (req, res) => {
    console.log(`Registering user. Form data : ${JSON.stringify(req.body)}`);

    //check the form data for needed criteria

    //check if all the inputs are provided
    await check('name', 'Name is required').notEmpty().run(req)
    await check('email', 'Email is required').notEmpty().run(req)
    await check('password', 'Password is required').notEmpty().run(req)
    await check('confirm_password', 'Confirm password is required').notEmpty().run(req)

    //check if email is in valid format
    await check('email', 'Email is in invalid format').isEmail().run(req)

    //check if password and confirm password matches
    await check('confirm_password', 'Password and confirm password must match')
    .equals(req.body.password).run(req)

    //get the validation result from express-validator
    const errors = validationResult(req).errors
    console.log(`errors : ${JSON.stringify(errors)}`);
    
    //if errors exist or not
    if (!errors || errors.length <= 0){
        try{
            //no errors, save the user to db
            
            //create User object
            const userToCreate = new User();
            userToCreate.name = req.body.name;
            userToCreate.email = req.body.email;
            // userToCreate.password = req.body.password;

            //generate hashed password
            bcrypt.genSalt(10, (err, salt) => {
                if (err){
                    //generating salt failed.
                    console.log(`Error while generating salt : ${JSON.stringify(err)}`);
                    res.status(500).send(`Cannot create account : ${JSON.stringify(err)}`)
                }else{
                    //salt generated; use it for password hashing
                    bcrypt.hash(req.body.password, salt, async (err, hashed_password) => {
                        if(err){
                            console.log(`Cannot generate hashed password : ${JSON.stringify(err)}`);
                            res.status(500).send(`Cannot generate hashed password : ${JSON.stringify(err)}`)
                        }else{
                            //hashed password generated successfully; save it to database
                            userToCreate.password = hashed_password
                            console.log(`hashed_password : ${hashed_password}`);
                            
                            //save object to db
                            const newUser = await userToCreate.save()

                            if(newUser){
                                console.log(`User account created successfully. ${JSON.stringify(newUser)}`)
                                res.redirect('/')
                            }else{
                                res.render('register', {errors: [{msg: 'Unable to create account'}]})
                            }
                        }
                    })
                }
            })

        }catch(error){
            console.log(`Error while creating account  : ${JSON.stringify(error)}`);
            res.render('register', {errors: [{msg: error}]})
        }
    }else{
        //show errors on UI
        console.log(`Error while registering user : ${JSON.stringify(errors)}`);
        res.render("register", {errors : errors})
    }
});

app.get("/logout", ensureLogin, (req, res) => {
    console.log(`Trying to log out.`)
    req.session.destroy()
    res.redirect("/login");
});

app.get("/login", (req, res) => {
    res.render("login");
})

app.post("/login", async (req, res) => {
    console.log(`Trying to login. Form data : ${JSON.stringify(req.body)}`);

    await check('email', 'Email is required').notEmpty().run(req)
    await check('password', 'Password is required').notEmpty().run(req)
    await check('email', 'Email is in invalid format').isEmail().run(req)

    //get the validation result from express-validator
    const errors = validationResult(req).errors
    console.log(`errors : ${JSON.stringify(errors)}`);
    
    if (!errors || errors.length <= 0){
        try{
            const emailFromUI = req.body.email
            const passwordFromUI = req.body.password

            //find the user from db with matching email
            const result = await User.find({email: emailFromUI})
            console.log(`result : ${JSON.stringify(result)}`);

            if(result){
                console.log(`result matches : matching user : ${emailFromUI}'`);

                const matchedUser = result[0];
                console.log(`matched user : ${JSON.stringify(matchedUser)}`);

                const hashedPassword = matchedUser.password
                //compare hashed password and user input password

                bcrypt.compare(passwordFromUI, hashedPassword , (err, success) => {
                    if (err){
                        console.log(`Error while validating password : ${JSON.stringify(err)}`);
                        res.render('login', {errors: [{msg: 'Invalid credential. Please try again.'}]})
                    }

                    if (success){
                        console.log(`Successful login.`);
                        req.session.loggedInUser = matchedUser
                        res.redirect('/')
                    }else{
                        console.log(`Invalid password : ${JSON.stringify(err)}`);
                        res.render('login', {errors: [{msg: 'Invalid credential. Please try again.'}]})
                    }
                })

            }else{
                console.log(`No matching user found`);
                res.render('login', {errors: [{msg: 'No matching user found. Please try again!'}]})
            }
        }catch(err){
            console.log(`Error while siging in  : ${JSON.stringify(err)}`);
            res.render('login', {errors: [{msg: err}]})
        }
    }else{
        //show errors on UI
        console.log(`Error while siging in user : ${JSON.stringify(errors)}`);
        res.render("login", {errors : errors})
    }
});

app.post("/insert", ensureLogin, async(req, res) => {

    const earliest = 1895;
    const currentYear = new Date().getFullYear();

    // validate year server-side (and any other fields you want)
    await check('year', `Year must be an integer between ${earliest} and ${currentYear}`)
      .notEmpty().isInt({ min: earliest, max: currentYear }).run(req);

    // you can also validate name/description/genre etc. as required
    await check('name', 'Name is required').notEmpty().run(req);
    await check('genre', 'Genre is required').notEmpty().run(req);

    const errors = validationResult(req).array();
    if (errors && errors.length > 0) {
        // render form with errors (client-side shows year help too)
        return res.render('insert', { errors: errors });
    }

    if (req.body){
        console.log(`Form data : ${JSON.stringify(req.body)}`)
        
        try{
            const movieToInsert = Movie({
                name: req.body.name,
                description: req.body.description,
                year: parseInt(req.body.year, 10),
                genre: req.body.genre,
                rating: req.body.rating ? Number(req.body.rating) : undefined,
                music: req.body.music,
                user: req.session.loggedInUser._id 
            })

            console.log(`movieToInsert : ${JSON.stringify(movieToInsert)}`);

            const savedMovie = await movieToInsert.save()


            if (savedMovie){
                console.log(`Document successfully inserted to DB : ${JSON.stringify(savedMovie)}`);
                res.redirect("/movielist")
            }else{
                console.log(`Error while saving the document.`);
                return res.status(500).send(`Error while saving the document.`)
            }

        }catch(err){
            console.log(`Error while inserting movie document : ${err}`);
            return res.send(`Error while inserting movie document : ${err}`)
            }
    } else {
    console.log(`No data received from form`);
    return res.send(`No data received from form. Please enter the data.`)
    }
})


app.get('/movielist', ensureLogin, async (req, res) => {
    try {
        console.log(`getting all movies`);
        const movies = await Movie.find()

        if (movies){
            console.log(`\nDocuments Received from DB : ${JSON.stringify(movies)}`)
            return res.render("movielist", {movielist : movies, error: req.query.error || null, message: req.query.message || null})
        }else{
            return res.send("No documents received from the database")
        }
    } catch (error) {
        res.status(500).send(error);
    }
});


//route to delete user document by ID
app.post("/delete/:id", ensureLogin, ensureUserIsOwner, async(req, res) => {
    console.log(`movie ID to delete : ${req.params.id}`);
    const idToDelete = req.params.id

    if (idToDelete){
        console.log(`Trying to delete document with ID : ${idToDelete}`);
        
        try{
            const deletedMovie = await Movie.findByIdAndDelete(idToDelete)
            const movies = await Movie.find()

            if (deletedMovie){
                console.log(`deleted movie : ${JSON.stringify(deletedMovie)}`)

                if (movies){
                    res.render('movielist', {
                        movielist : movies, 
                        message: `Movie deleted successfully`,
                        error: null
                    })
                }else{
                    res.redirect("/movielist")
                }
            }else{
                console.log(`No such Movie exist`);
                res.render('movielist', {movielist : movies, message: `No such movie exist`, error: null})
            }

        }catch(err){
            console.log(`Error while deleting movie : ${JSON.stringify(err)}`);
            return res.render('movielist', {movielist : movies, message: null, error : err})
        }
    }else{
        console.log(`No document with given id exist`);
        res.render('movielist', {movielist : movies, message: null, error : `No document with given id exist`})
    }
})


app.get("/update/:id", ensureLogin, async(req, res) => {
    console.log(`movie ID to update : ${req.params.id}`);
    const idToUpdate = req.params.id

    if (idToUpdate){
        console.log(`Trying to show data from document with ID : ${idToUpdate}`);
        try{
            const movie = await Movie.findById(idToUpdate)

            if(movie){
                res.render('update', {movieToEdit: movie})
            }else{
                console.log(`Error: Unable to find movie with given ID.`);
                res.render('update', {error: `Error: Unable to find movie with given ID.`})
            }
        }catch(err){
            console.log(`Error while showing existing movie data. ${JSON.stringify(err)}`);
            res.render('update', {error: `Error: No such movie exist. ${JSON.stringify(err)}`})
        }
    }else{
        console.log(`Error: ID not provided.`);
        res.render('update', {error: `Error: ID not provided.`})
    }
})


app.post("/update/:id", ensureLogin, ensureUserIsOwner, async(req, res) => {
    const earliest = 1895;
    const currentYear = new Date().getFullYear();

    await check('year', `Year must be an integer between ${earliest} and ${currentYear}`)
      .notEmpty().isInt({ min: earliest, max: currentYear }).run(req);
    await check('name', 'Name is required').notEmpty().run(req);
    await check('genre', 'Genre is required').notEmpty().run(req);

    const errors = validationResult(req).array();
    if (errors && errors.length > 0) {
        // re-render update page with movie data and errors
        const movie = await Movie.findById(req.params.id);
        return res.render('update', { movieToEdit: movie, error: errors });
    }

    // when building updated object, ensure year is a Number
    try{
        const updatedMovieObj = {
            name: req.body.name,
            description: req.body.description,
            year: parseInt(req.body.year, 10),
            genre: req.body.genre,
            rating: req.body.rating ? Number(req.body.rating) : undefined,
            music: req.body.music,
            user: req.movie.user // keep original owner (ensureUserIsOwner set req.movie)
        }
        console.log(`updatedMovieObj : ${JSON.stringify(updatedMovieObj)}`);

        const movie = await Movie.findByIdAndUpdate(
            idToUpdate, 
            updatedMovieObj, 
            {new: true}
        )

        if(movie){
            res.redirect('/movielist')
        }else{
            console.log(`Error: Unable to updated the movie information.`);
            res.render('update', {error: `Error: Unable to updated the movie information`})
        }
    }catch(err){
        console.log(`Error while saving updated document. ${JSON.stringify(err)}`);
        res.render('update', {error: `Error: Error while saving updated document. 
            ${JSON.stringify(err)}`})
    }
})


const connectDB = async() => {
    try{
        console.log(`Attempting to connect to DB`);
        mongoose.connect(process.env.MONGO_URI, {dbName: "Movie"})
        .then(() => console.log(`Database connection established successfully.`))
        .catch( (err) => 
            console.log(`Can't established database connection : ${JSON.stringify(err)}`))
    }catch(error){
        console.log(`Unable to connect to DB : ${error.message}`);
        
    }
}

const onServerStart = () => {
    console.log(`The server started running at http://localhost:${PORT}`);
    console.log(`Press Ctrl+c to stop`);
    connectDB()
}
app.listen(PORT, onServerStart)

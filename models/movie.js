const mongoose = require('mongoose')

const movieSchema = new mongoose.Schema({
    name : {
        type : String,
        required : true,
        unique: true, //Ensured that studentID is unique throughout the collection (Primary key)
        index: true
    },
    description : {
        type : String,
        required : true
    },
    year : {
        type : Number,
        required : true
    },
    genre : {
        type : String,
        required : true
    },
    rating : {
        type : Number,
        required : false
    },
})

let Movie = mongoose.model("Movie", movieSchema)
module.exports = Movie
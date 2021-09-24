const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const connection = require('../utils/connection');


const courseSchema = new Schema({

    title: {
        type: String
    },

    description: {
        type: String
    },

    link: {
        type: String
    },

    videoNames: [String],
    videos: [String]

})

const Course = connection.model('Course', courseSchema);


module.exports = Course;



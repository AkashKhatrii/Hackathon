const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const connection = require('../utils/connection');

const questionSchema = new Schema({

    course: {
        type: String
    },

    question: {
        type: String
    },

    options: {
        type: [String]
    },

    answer: {
        type: String
    }

})

const Question = connection.model("Question", questionSchema);

module.exports = Question;
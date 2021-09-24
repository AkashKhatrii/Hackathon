const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const connection = require('../utils/connection');


const videoSchema = new Schema({
    vname: String,

}, {timestamps: true});

const Video = connection.model('Video', videoSchema);

module.exports = Video;

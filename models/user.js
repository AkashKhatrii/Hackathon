const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const findOrCreate = require('mongoose-findorcreate');
const connection = require('../utils/connection');


const UserSchema = new Schema({
    username: String,
    hash: String,
    salt: String,
    googleId: String,
    admin: Boolean
});

UserSchema.plugin(findOrCreate)
const User = connection.model('User', UserSchema);


module.exports = User;
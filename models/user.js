const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    tokens: [{ token: String }]
  });

module.exports= mongoose.model('User', userSchema)
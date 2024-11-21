const mongoose = require('mongoose')

const User = mongoose.model('User', {
    name:String,
    pass:String,
})

module.exports = User
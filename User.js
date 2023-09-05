const { Schema, model } = require("mongoose");

const userSchemaa = new Schema({
  name: {
    type: String,
    require: true,
  },
  email: {
    type: String,
    require: true,
    unique: true,
  },
});

module.exports = model("User", userSchemaa);

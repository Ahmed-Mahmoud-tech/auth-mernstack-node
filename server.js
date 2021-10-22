const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const routesUrls = require('./routers/routers')
const cors = require('cors');

//require('crypto').randomBytes(64).toString('hex')
dotenv.config()


mongoose.connect(process.env.DATABASE_ACCESS, { useNewUrlParser: true , useUnifiedTopology: true});
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));


app.use(express.json());
app.use(cors());
app.use('/app', routesUrls);
app.listen(4000, ()=> console.log("server is up and running"))

//https://www.youtube.com/watch?v=mbsmsi7l3r4&t=36s
// 20 min
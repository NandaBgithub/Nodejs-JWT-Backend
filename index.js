// Nodejs common modules
const https = require('node:https');                                       
const fs = require('node:fs');                             

// NPM modules
require('dotenv').config()               

// User declared modules
const {register, login, validateToken} = require('./controller/authentication.js')


// To set up a mongo db connection
const {MongoClient} = require("mongodb")
const connectionString = process.env.MONGODB_CONNECTION_STRING
const client = new MongoClient(connectionString)
const database = client.db('summer')
const usersCollection = database.collection('users')

async function connect(){
    try {
        // const dbstatus = await database.stats()

        console.log("SUCCESS: Connected to database sucessfully")
        //console.log("Database statistics", {db: dbstatus.db, collections: dbstatus.collections})
    } catch {
        console.error("ERROR: Server connection error")
    } 
};
connect();  // Connect to database

/*
    options object used to set server related configurations
    eg. 
        - Accepted content types
        - Server timeouts
        - Persistent connection setting
        - Keys and certificates
*/
const options = {
    key: fs.readFileSync('./ps/private-key.pem'),       // get private key
    cert: fs.readFileSync('./ps/certificate.pem'),      // certificate for now is "self signing"
};

/* 
    Backend entry point to routes
*/
const server = https.createServer(options, (req, res) => {
    if (req.url === "/api/auth/register" 
        && req.method === 'POST'){

        register(req, res, usersCollection)

    } else if (req.url === "/api/auth/login" && req.method === 'POST'){

        login(req, res, usersCollection)

    } else if (req.url === "/api/protected-route" && req.method === 'GET'){ 
        // This route is used to test validateToken yeurrrrr 
        validateToken(req, res)
    }else {
        res.statusCode = 404
        res.end('Page Not Found') 
    }
})

server.listen(process.env.BACKEND_DEVELOPMENT_PORT,() => {
    console.log(`SUCCESS: Server listening on port ${process.env.BACKEND_DEVELOPMENT_PORT}`)
});
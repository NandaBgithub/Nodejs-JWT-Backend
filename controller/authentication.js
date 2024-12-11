require("mongodb")
require('dotenv').config()
const jwt = require('jsonwebtoken')
const cookie = require('cookie')
const bcrypt = require("bcrypt")
const saltRounds = 10;

function register(req, res, usersCollection){
    let buffer = ''
    let body = {}
    let userId

    req.on('data', chunk => {
        buffer += chunk
    }).on('end', () => {
        const parsedBody = JSON.parse(buffer)
        const {username, email, password} = parsedBody

        // Hash password
        bcrypt.hash(password, saltRounds, (err, hash) => {
            body = {username: username, email: email, password: hash}
            // Check email already exists in collection
            usersCollection.findOne({username: username, email: email}).then((document)=>{
                if (document == null) {
                    // After hashing insert document into users collection
                    usersCollection.insertOne(body).then((doc) => {
                        userId = doc.insertedId
                        console.log(`hashed req.body = {email: ${email}, password: ${hash}}`)

                        // create jwt access token that expires in 2 minutes
                        let accesstoken = jwt.sign(body, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 120})
                        // refresh token expires in 3 days
                        let refreshtoken = jwt.sign(body, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '3d'})
                        
                        res.setHeader("Set-Cookie",
                            cookie.serialize("refresh_token", refreshtoken, 
                                    {path: '/', httpOnly: true, maxAge: 60 * 60 * 24 * 3})
                        )

                        // send response
                        res.writeHead(200, {'Content-Type': 'application/json'})
                        res.end(JSON.stringify({id: userId, token: accesstoken}))
                    }).catch(error => {
                        console.log("ERROR: ", error)
                    })
                } else {
                    // user already exist
                    res.writeHead(401, {'Content-Type': 'application/json'})
                    res.end("User already exists")
                }
            })
        })
    })
    

} 

function login(req, res, usersCollection){
    // TODO: process req and validate user credentials
    let buffer = ''
    let body = {}
    
    req.on('data', chunk => {
        buffer += chunk
    }).on('end', () => {
        const {username, password} = JSON.parse(buffer)

        // Check if password is correct
        usersCollection.findOne({username: username}).then((document) => {
            // console.log("LOGIN BODY ", document)
            // console.log("hashed password", body)
            if (document !== null){
                bcrypt.compare(password, document.password, (err, match)=>{
                    if (match) {
                        let userId = document._id
                        let accesstoken = jwt.sign(body, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 120})
                        let refreshtoken = jwt.sign(body, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '3d'})
        
                        res.setHeader("Set-Cookie", 
                            cookie.serialize("refresh_token", refreshtoken, {path: '/', httpOnly: true, maxAge: 60*60*24*3})
                        )
        
                        res.writeHead(200, {'Content-type': 'application/json'})
                        res.end(JSON.stringify({id: userId, token: accesstoken}))
                    } else if (!match){
                        console.log(err)
                        res.writeHead(401, {'Content-type': 'text/plain'})
                        res.end("Incorrect login")
                    }
                })

            } else {
                res.writeHead(401, {'Content-type': 'text/plain'})
                res.end("Incorrect login")
            }
        })
    })
}

// Possible improvement, check user that sent the cookie
function validateToken(req, res){
    let buffer = ''
    
    req.on('data', chunk => {
        buffer += chunk
    }).on('end', ()=>{
        const {id} = JSON.parse(buffer)
        let userCookie = cookie.parse(req.headers.cookie || '')
        let refreshCookie = userCookie.refresh_token ? userCookie.refresh_token : null

        // check validity of the refresh token
        if (refreshCookie !== null){
            jwt.verify(refreshCookie, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
                if (err !== null){
                    if (err.name === 'JsonWebTokenError'){
                        // invalid refresh token
                        res.writeHead(401, {'Content-type': 'text/plain'})
                        res.end("Incorrect login")
                    }  else {
                        // expired refresh token, assign new one
                        let newRefresh = jwt.sign({id: id}, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '3d'})
                        let newAccess = jwt.sign({id: id}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 120})
        
                        res.setHeader("Set-Cookie", 
                            cookie.serialize('refresh_token', newRefresh, {path: '/', httpOnly: true, maxAge: 60*60*24*3}))
        
                        res.writeHead(200, {'Content-type': 'application/json'})
                        res.end(JSON.stringify({id: id, accesstoken: newAccess}))
                    }
                } else {
                    // refresh is still active, generate new access token
                    let newAccess = jwt.sign({id: id}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 120})
                    console.log("Existing cookie", refreshCookie)
                    
                    res.setHeader("Set-Cookie", 
                        cookie.serialize('refresh_token', refreshCookie, {path: '/', httpOnly: true, maxAge: 60*60*24*3}))
    
                    res.writeHead(200, {'Content-type': 'application/json'})
                    res.end(JSON.stringify({id: id, accesstoken: newAccess}))
                }
            })
        } else{
            res.writeHead(401, {'Content-type': 'text/plain'})
            res.end("Incorrect login")     
        }
    })
}

module.exports = {
    register: register,
    login: login,
    validateToken: validateToken
}
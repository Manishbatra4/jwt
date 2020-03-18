require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const {verify} = require('jsonwebtoken');
const {hash, compare} = require('bcrypt');

const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require("./token");
const {fakeDB} = require('./fakeDB');
const {isAuth} = require('./isAuth');

// 1. Register a Use
// 2. Login a User
// 3. Logout a User
// 4. Setup a Protected route
// 5. Get a new access token with a refresh token

// evoking express server
const server = express();

// Middleware
server.use(cookieParser());

server.use(
    cors({
        origin: 'http://localhost:3000',
        credential: true
    })
);

//need to be able to read body data
server.use(express.json()); // to support json-encoder bodies
server.use(express.urlencoded({extended: true})); //Support url-encoded bodies

server.listen(process.env.PORT, () => {
    console.log('http://localhost:' + process.env.PORT)
});

// 1. Register a User

server.post('/register', async (req, res) => {
    const {email, password} = req.body;

    try {
        const user = fakeDB.find(user => user.email === email);
        if (user) throw new Error('user already exist')
        const hashedPassword = await hash(password, 10);
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        });
        res.send({message: "User Created"});
        console.log(fakeDB);
    } catch (e) {
        res.send({
            error: `${e.message}`,
        });
    }
});


// 2. Login a user
server.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Find user in array. If not exist send error
        const user = fakeDB.find(user => user.email === email);
        if (!user) throw new Error('User does not exist');
        // 2. Compare crypted password and see if it checks out. Send error if not
        const valid = await compare(password, user.password);
        if (!valid) throw new Error('Password not correct');
        // 3. Create Refresh- and Accesstoken
        const accesstoken = createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        // 4. Store Refreshtoken with user in "db"
        // Could also use different version numbers instead.
        // Then just increase the version number on the revoke endpoint
        user.refreshtoken = refreshtoken;
        // 5. Send token. Refreshtoken as a cookie and accesstoken as a regular response
        sendRefreshToken(res, refreshtoken);
        sendAccessToken(res, req, accesstoken);
    } catch (err) {
        res.send({
            error: `${err.message}`,
        });
    }
});

server.post("/logout", async (request, response) => {
   response.clearCookie('refreshToken');
   return response.send({
       message: 'logout'
   })
});

server.post('/protected', async (req, res) => {
    try {
        const userID = isAuth(req);
        console.log(userID);
        if (userID !== null) {
            res.send({
                data: "This is Protected Data"
            })
        }
    }catch (e) {
        res.send({
            error: `${e.message}`
        })
    }
});

server.post("/refresh_token", async (req, res) => {
    const token = req.cookie.refreshToken;
});
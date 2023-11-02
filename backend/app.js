const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const users = require('./users');
const axios = require('axios');
const apiflask="http://127.0.0.1:5000";

 const refreshTokens =require("./refreshtoken")
console.log(users)
const app = express();
const port = process.env.PORT || 3000;
const secretKey = 'your-secret-key';

app.use(bodyParser.json());
 //Registration endpoint
 app.post('/register', (req, res) => {
   const { username, password } = users[0];
     console.log("hello")
   const user = users.find((user) => user.username === username);
   if (user) {
     return res.status(401).json({ message: 'user is already registered' });
   }
   if (!username || !password) {
     console.log("hi")
     return res.status(400).json({ message: 'Username and password are required' });
   }
   // Hash the password before storing it in the database (replace this with your database logic)
   const hashedPassword = bcrypt.hashSync(password, 10);
   console.log("password")
   // Store the user data (in-memory database in this example)
   user.push({ username, password: hashedPassword });
   console.log(users)
   res.status(201).json({ message: 'Registration successful' });
 });
 // Login endpoint
 app.post('/login', (req, res) => {
   const { username, password } = users[0];
   const user = users.find((user) => user.username === username);
   if (!user) {
     return res.status(401).json({ message: 'Authentication failed3' });
   }
   // Check the password using bcrypt
   if (bcrypt.compareSync(password, user.password)) {
     // Generate a JWT token and send it as a response
     const token = generateJWTToken(user);
     const refreshToken = generateRefreshToken();
     res.json({ token });
     console.log(refreshToken)
   } else {
     res.status(401).json({ message: 'Authentication 5failed' });
   }
 });
 // Middleware to protect routes
 function authenticateToken(req, res, next) {
   console.log("hi")
   console.log(req)
   const token1 = req.header('Authorization');
   const token ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7InVzZXJuYW1lIjoidXNlciIsInBhc3N3b3JkIjoiJDJhJDEwJHM1djNELmpQSTdham52N2N5WjloVk9jVzU4bkE3NXdYeWNZcVRLSHZHNlpHS1JkSXdTbm9GIn0sImlhdCI6MTY5ODk0MTU4MywiZXhwIjoxNjk4OTQyNDgzfQ.BVjU7fANmyPjBkChdPKo3SlseWf1dPrbaspOE9j1UhA"
    console.log(token)
   if (!token) {
     return res.status(401).json({ message: 'Access denied. Token missing.' });
   }
   jwt.verify(token, secretKey, (err, user) => {
     if (err) return res.status(403).json({ message: 'Access denied. Token invalid.' });
     req.user = user;
     next();
   });
 }
 // A protected route that requires authentication
 app.get('/protected', authenticateToken, (req, res) => {
   res.json({ message: 'This is a protected route.' });
 });
 // Generate a new access token using a refresh token
 app.post('/token', (req, res) => {
   const refreshToken = req.body.refreshToken;
   if (!refreshToken || !refreshTokens.includes(refreshToken)) {
     return res.status(401).json({ message: 'Invalid refresh token' });
   }
   jwt.verify(refreshToken, secretKey, (err, user) => {
     if (err) {
       return res.status(403).json({ message: 'Invalid refresh token' });
     }
     const accessToken = generateJWTToken({ username: user.username });
     res.json({ accessToken });
   });
 });
 // Logout endpoint to invalidate a refresh token
 app.delete('/logout', (req, res) => {
   const refreshToken = req.body.refreshToken;
   if (refreshToken) {
     const index = refreshTokens.indexOf(refreshToken);
     if (index !== -1) {
       refreshTokens.splice(index, 1);
     }
   }
   res.status(204).send();
 });
 // Function to generate a JWT token (access token)
 function generateJWTToken(user) {
   return jwt.sign({user}, secretKey, { expiresIn: '15m' });
 }
 // Function to generate a refresh token
 function generateRefreshToken() {
   const refreshToken = jwt.sign({}, secretKey, { expiresIn: '7d' });
   refreshTokens.push(refreshToken);
   return refreshToken;
 }



// Decode and verify an access token
const decodeAccessToken = (accessToken) => {
  try {
      const payload = jwt.verify(accessToken, secretKey);
      return payload;
  } catch (err) {
      return err.message;
  }
};

const userId = users[0]
const accessToken = generateJWTToken(userId);
const refreshToken = generateRefreshToken(userId);

console.log(`Access Token: ${accessToken}`);
console.log(`Refresh Token: ${refreshToken}`);

const decodedAccessToken = decodeAccessToken(accessToken);
console.log('Decoded Access Token:', decodedAccessToken);
axios.post("http://127.0.0.1:5000/receive_tokens", {
  
  accessToken: accessToken,
  refreshToken: refreshToken,
  
})
  .then(response => {
    console.log('Tokens sent successfully to Flask:', response.data);
  })
  .catch(error => {
    console.error('Failed to send tokens to Flask:', error);
  });

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

//const encryptionKey = crypto.randomBytes(32).toString('hex'); 

// Retrieve the encryption key from environment variable
const encryptionKey = process.env.NOT_MY_KEY;

if (!encryptionKey) {
  console.error('FATAL ERROR: encryption key is not defined.');
  process.exit(1);
}

let db = new sqlite3.Database('./totally_not_my_privateKeys.db')

// Create users table if it doesn't exist
db.serialize(() => {
  db.run('DROP TABLE IF EXISTS keys')

  db.run(`CREATE TABLE IF NOT EXISTS keys(
          kid INTEGER PRIMARY KEY AUTOINCREMENT,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL)`)

  db.run('DROP TABLE IF EXISTS users')

  db.run(`CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          email TEXT UNIQUE,
          date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_login TIMESTAMP )`)
  
  db.run('DROP TABLE IF EXISTS auth_logs')

  db.run(`CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id))`);
});

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true)
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

// Function to encrypt a private key using AES
const encryptPrivateKey = (privateKey) => {
  const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(encryptionKey, 'hex'), crypto.randomBytes(16));
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted.toString('base64') ;
};

// Function to decrypt an encrypted private key using AES
const decryptPrivateKey = (encryptedPrivateKey) => {
  const buff = Buffer.from(encryptedPrivateKey, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-ctr', Buffer.from(encryptionKey, 'hex'), crypto.randomBytes(16));
  let decrypted = decipher.update(buff, 'hex', 'utf8') + decipher.final('utf8')
  return decrypted;
};


async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  return [keyPair, expiredKeyPair]
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  //encrypt the private key
  var encryptedPrivateKey = encryptPrivateKey(keyPair.toPEM(true))
  console.log(keyPair.toPEM(true) + '\n')
  console.log(decryptPrivateKey(encryptedPrivateKey))
  //store key in db
  db.run('INSERT INTO keys(key, exp) VALUES(?,?)',[encryptedPrivateKey, payload.exp], error => {
    if (error) throw error;
    console.log('Valid key stored in db')
  })

  //retrive valid key from db
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT key FROM keys WHERE exp > ?', [now], (error, row) => {
    if(error) throw error;
    //decrypt the private key
    //console.log(row[0].key)
    //decryptedPrivateKey = decryptPrivateKey(row[0].key)
    token = jwt.sign(payload, row[0].key, options);
  })
  
  return token;
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  //store key in db
  db.run('INSERT INTO keys(key, exp) VALUES(?,?)',[expiredKeyPair.toPEM(true), payload.exp], error => {
    if (error) throw error;
    console.log('Expired key stored in db')
  })

  //retrieve expired key from db
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT key FROM keys WHERE exp <= ?', [now], (error, row) => {
    if(error) throw error;
    expiredToken = jwt.sign(payload, row[0].key, options);
  })
  return expiredToken;
}

// Generate secure password using uuidv4
function generateSecurePassword() {
  return uuidv4();
}

// Hash the secure password using uuidv4
async function hashSecurePassword(securePassword) {
  try{
    securePassword = await argon2.hash(securePassword,
      { type: argon2.argon2id,
        hashLength:65,
        timeCost: 2,
      });
  }catch(err){
    console.log(err);
  }
  return securePassword;
}

// Middleware to ensure only POST requests are allowed for /auth
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {

  // get valid key from db
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT * FROM keys WHERE exp > ?', [now], (error, row) => {
    if(error) throw error;
    if (row[0].key === keyPair.toPEM(true)){
      const validKeys = [keyPair].filter(key => !key.expired);
      res.setHeader('Content-Type', 'application/json');
      res.json({ keys: validKeys.map(key => key) });
    }
  })
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){

    const request_ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const username = req.body.username;
    //const ip_addr = req.ip;
    const request_timestamp = Math.floor(Date.now() / 1000);
    db.run('SELECT id FROM users WHERE username = ?', [username], (error, row) => {
      if(error) throw error;
      user_id = row[0].id;
    })

    db.run('INSERT INTO auth_logs(request_ip, request_timestamp, user_id) VALUES(?,?,?)',
    [request_ip, timestamp, user_id], error => {
       if (error) throw error;
       console.log('New request log added to the db')
    });
    return res.send(expiredToken);
  }
  res.send(token);
});

// Middleware to ensure only POST requests are allowed for /register
app.all('/register', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.post('/register', (req, res) => {
  const {username, email} = req.body;
  if (!username || !email) {
    return res.status(400).json({error:'Bad Request'});
  }

  //Generate a secure password and hash it
  const password = generateSecurePassword();
  const hashedPassword = hashSecurePassword(password);

  //Add user credentials to the users databse
  
  //const date_registered = Math.floor(Date.now() / 1000);
  //const last_login = Math.floor(Date.now() / 1000);

  db.run('INSERT INTO users(username, password_hash, email, date_registered, last_login) VALUES(?,?,?)',
         [username, hashedPassword, email], error => {
            if (error) throw error;
            console.log('New user added to the db')
  })

  //return status code and unhashed password to user
  return res.status(201).send({"password": password});
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
module.exports = {app, generateKeyPairs, generateToken, generateExpiredJWT};

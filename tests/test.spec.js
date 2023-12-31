const chai = require('chai');
const chaiHttp = require('chai-http');
const {app, generateKeyPairs, generateToken, generateExpiredJWT, encryptPrivateKey, decryptPrivateKey, generateSecurePassword, hashSecurePassword} = require('../server.js');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const expect = chai.expect;
chai.use(chaiHttp);

describe('Server', () => {
  before((done) => {
    // Initialize and seed the database before running tests
    db = new sqlite3.Database('./totally_not_my_privateKeys.db');
    db.serialize(() => {
      db.run('DELETE FROM keys'); // Clear the keys table
      done();
    });
    setTimeou
    
  });
  
  describe('generateKeyPairs', () => {
    it('generate a set of valid and expired key pairs', async () => {
      const [resultKeyPair, resultExpiredKeyPair] = await generateKeyPairs();
      //console.log('resultKeyPair:', resultKeyPair);
      //console.log('resultExpiredKeyPair:', resultExpiredKeyPair);

      // Check that keyPair and expiredKeyPair are defined
      expect(resultKeyPair).to.be.an('object');
      expect(resultExpiredKeyPair).to.be.an('object');
    });
  });

  describe('generateExpiredJWT', () => {
    it('generate an expired JWT token and retrieve from the database', async () => {
      const token = await generateExpiredJWT();
      //console.log('token:', token);

      //check that key is stored in db
      db = new sqlite3.Database('./totally_not_my_privateKeys.db');
      let now = Math.floor(Date.now() / 1000)
      db.all('SELECT key FROM keys WHERE exp < ?', [now], (error, row) => {
        if(error) throw error;
        expect(row[0].key).to.be.a('string');
      })

      //check that token is a string
      expect(token).to.be.a('string');
    });
  });

  describe('encryptPrivateKey', () => {
    
    it('encrypt a private key', async () => {
      const [resultKeyPair, resultExpiredKeyPair] = await generateKeyPairs();
      const encryptedPrivateKey = await encryptPrivateKey(resultKeyPair.toPEM(true));
      //console.log('encryptedPrivateKey:', encryptedPrivateKey);

      //check that encryptedPrivateKey is a string
      expect(encryptedPrivateKey).to.be.a('string');
    });
  })

  describe('DecryptPrivateKey', () => {
    it('decrypt encrypted private key', async () => {
      const [resultKeyPair, resultExpiredKeyPair] = await generateKeyPairs();
      const encryptedPrivateKey = await encryptPrivateKey(resultKeyPair.toPEM(true));
      const decryptedPrivateKey = await decryptPrivateKey(encryptedPrivateKey);
      //console.log('decryptedPrivateKey:', decryptedPrivateKey);

      //check that encryptedPrivateKey is a string
      expect(decryptedPrivateKey).to.be.equal(resultKeyPair.toPEM(true));
      expect(decryptedPrivateKey).to.be.a('string');
    });
  })
  
  describe('generateSecurePassword', () => {
    it('generate a secure password', async () => {
      const securePassword = await generateSecurePassword();
      //console.log('securePassword:', securePassword);

      //check that securePassword is a string
      expect(securePassword).to.be.a('string');
    });
  })

  describe('hashSecurePassword', () => {
    it('hash a secure password', async () => {
      const securePassword = await generateSecurePassword();
      const hashedSecurePassword = await hashSecurePassword(securePassword);
      //console.log('hashedSecurePassword:', hashedSecurePassword);

      //check that hashedSecurePassword is a string
      expect(hashedSecurePassword).to.be.a('string');
    });
  })


  describe('generateToken', () => {
    it('generate a valid token and retrieve from the database', async () => {
      const token = await generateToken();

      //check that key is stored in db
      db = new sqlite3.Database('./totally_not_my_privateKeys.db');
      let now = Math.floor(Date.now() / 1000)
      db.all('SELECT key FROM keys WHERE exp > ?', [now], (error, row) => {
        if(error) throw error;
        expect(row[0].key).to.be.a('string');
      })

      //check that token is a string
      expect(token).to.be.a('string');
    });
  });

  describe('GET /.well-known/jwks.json', () => {
    it('should return a JSON array of valid keys', async (done) => {
      chai
        .request(app)
        .get('/.well-known/jwks.json')
        .end((err, res) => {
          expect(res).to.have.status(200);
          expect(res).to.be.json;
          done();
        });
    });
  });

  describe('Server', () => {
    it('should return a 405 status code for non-POST requests to /auth', (done) => {
      chai
        .request(app)
        .get('/auth')
        .end((err, res) => {
          expect(res).to.have.status(405);
          expect(res.text).to.equal('Method Not Allowed');
          done();
        });
    });
  });

  describe('jwkServer', () => {
    it('should return a 405 status code for non-GET requests to /.well-known/jwks.json', (done) => {
      chai
        .request(app)
        .post('/.well-known/jwks.json')
        .end((err, res) => {
          expect(res).to.have.status(405);
          expect(res.text).to.equal('Method Not Allowed');
          done();
        });
    });
  });


  describe('POST /auth', () => {
    it('should return a valid JWT token', async (done) => {
      chai
        .request(app)
        .post('/auth')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });

    it('should return an expired JWT token when requested', async (done) => {
      chai
        .request(app)
        .post('/auth?expired=true')
        .end((err, res) => {
          expect(res).to.have.status(200);
          done();
        });
    });
  });
  
  describe('POST /register', () => {
    it('should give user a hashed password', async (done) => {
      chai
        .request(app)
        .post('/register')
        .end((err, res) => {
          expect(res).to.have.status(201);
          expect(res).to.be.json;
          done();
        });
    });
  });
});



// Clean up after all tests (close the database connection)
after((done) => {
  db.close((err) => {
    if (err) {
      console.error('Error closing the database:', err);
    }
    done();
  });
});

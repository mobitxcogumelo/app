const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const admin = require('firebase-admin');

admin.initializeApp(); // via GOOGLE_APPLICATION_CREDENTIALS ou service account

const FB_JWKS_URI = 'https://www.facebook.com/.well-known/oauth/openid/jwks/';
const FB_ISS = 'https://www.facebook.com';
const FB_APP_ID = process.env.FB_APP_ID; // obrig: seu Facebook App ID

const client = jwksClient({ jwksUri: FB_JWKS_URI });
function getKey(header, cb) {
  client.getSigningKey(header.kid, (err, key) => cb(err, key && key.getPublicKey()));
}

const app = express();
app.use(express.json());

app.post('/exchange', (req, res) => {
  const { authenticationToken } = req.body || {};
  if (!authenticationToken) return res.status(400).send('Missing authenticationToken');

  jwt.verify(authenticationToken, getKey, {
    algorithms: ['RS256'],
    issuer: FB_ISS,
    audience: 761748226355973, // tem que ser seu App ID do Facebook
  }, async (err, decoded) => {
    if (err) return res.status(401).send(`Invalid Facebook OIDC: ${err.message}`);

    try {
      const uid = `facebook:${decoded.sub}`;
      const claims = { name: decoded.name, email: decoded.email };
      const customToken = await admin.auth().createCustomToken(uid, claims);
      res.json({ customToken });
    } catch (e) {
      res.status(500).send(`Failed to create custom token: ${e.message}`);
    }
  });
});

app.listen(process.env.PORT || 8080, () => console.log('Auth server UP'));
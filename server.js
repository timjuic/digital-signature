const express = require('express');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
// Generate and save a secret key
app.get('/generateSecretKeyEndpoint', async (req, res) => {
    const secretKey = crypto.randomBytes(32).toString('hex');
    console.log("SECRET", secretKey);
    await saveKeyToFile('secret_key.txt', secretKey);
    res.send(secretKey);
});

// Generate and save a public key
app.get('/generatePublicKeyEndpoint', async (req, res) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    await saveKeyToFile('public_key.txt', publicKey);

    res.send(publicKey);
});

// Generate and save a private key
app.get('/generatePrivateKeyEndpoint', async (req, res) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    await saveKeyToFile('private_key.txt', privateKey);

    res.send(privateKey);
});

async function saveKeyToFile(fileName, key) {
    const filePath = path.join(__dirname, fileName);
    await fs.writeFile(filePath, key);
    console.log(`${fileName} saved to ${filePath}`);
}

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

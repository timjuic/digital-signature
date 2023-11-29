const express = require('express');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const cors = require('cors');
const multer  = require('multer')
const upload = multer()
const app = express();
const port = 3000;

app.use(cors());
// Generate and save a secret key
// app.get('/generateSecretKeyEndpoint', async (req, res) => {
//     const secretKey = crypto.randomBytes(32).toString('hex');
//     console.log("SECRET", secretKey);
//     await saveToFile('secret_key.txt', secretKey);
//     res.send(secretKey);
// });
//
// // Generate and save a public key
// app.get('/generatePublicKeyEndpoint', async (req, res) => {
//     const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
//         modulusLength: 2048,
//         publicKeyEncoding: { type: 'spki', format: 'pem' },
//         privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
//     });
//
//     await saveToFile('public_key.txt', publicKey);
//
//     res.send(publicKey);
// });

// Generate and save a private key
// app.get('/generatePrivateKeyEndpoint', async (req, res) => {
//     const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
//         modulusLength: 2048,
//         publicKeyEncoding: { type: 'spki', format: 'pem' },
//         privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
//     });
//
//     await saveToFile('private_key.txt', privateKey);
//
//     res.send(privateKey);
// });


app.post('/processFile/asymmetric', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');
        console.log("fileContent", fileContent)

        const { encryptedText, publicKey, privateKey } = await encryptAsymmetric(fileContent);
        await saveToFile('private_key.txt', privateKey);
        await saveToFile('public_key.txt', publicKey);

        console.log('Encripted text', encryptedText)
        await saveToFile('asymmetric_encrypted_text.txt', encryptedText);

        // Generate a digital signature
        const signature = await signText(fileContent);
        console.log("signature", signature)

        // Save the digital signature to a separate file
        await saveToFile('digital_signature.txt', signature);

        const hash = calculateHash(fileContent);
        await saveToFile('hash.txt', hash)

        res.status(200).send('Asymmetric encryption with digital signature completed successfully');
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Endpoint for symmetric encryption
app.post('/processFile/symmetric', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        // Perform symmetric encryption logic (use a secure encryption library or algorithm)
        // For demonstration purposes, using a simple Caesar cipher
        console.log("CONTENT", fileContent)
        const encryptedText = await encryptSymmetric(fileContent);

        // Save the encrypted text to a file
        await saveToFile(encryptedText, 'symmetric_encrypted_text.txt');

        res.status(200).send('Symmetric encryption completed successfully');
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});


async function encryptAsymmetric(text) {
    // Generate key pair (public key and private key)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Use the public key to encrypt the content
    const encryptedText = crypto.publicEncrypt(publicKey, Buffer.from(text, 'utf-8')).toString('base64');

    return { encryptedText, publicKey, privateKey };
}

async function signText(text) {
    // Use the private key to create a digital signature
    const privateKey = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }).privateKey;

    const signature = crypto.sign('sha256', Buffer.from(text, 'utf-8'), { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });

    return signature.toString('base64');
}

function calculateHash(text) {
    // Perform hash calculation logic (use a secure hashing library or algorithm)
    // For demonstration purposes, using Node.js built-in crypto library
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    return hash;
}


async function saveToFile(fileName, content) {
    const filePath = path.join(__dirname, fileName);
    await fs.writeFile(filePath, content);
    console.log(`${fileName} saved to ${filePath}`);
}

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

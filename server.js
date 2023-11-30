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


app.post('/asymmetricEncryption', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        // Calculate the hash of the original data before encryption
        const hash = calculateHash(fileContent);

        // Encrypt the original data and its hash
        const { encryptedText, publicKey, privateKey } = await encryptAsymmetric(fileContent + hash);
        await saveToFile('private_key.txt', privateKey);
        await saveToFile('public_key.txt', publicKey);
        await saveToFile('asymmetric_encrypted_text.txt', encryptedText);

        const signature = await signText(fileContent);

        // Save the digital signature to a separate file
        await saveToFile('digital_signature.txt', signature);

        // Save the hash to a separate file
        await saveToFile('hash.txt', hash);

        res.status(200).send('Asymmetric encryption with digital signature and hashing completed successfully');
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.post('/asymmetricDecryption', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        // Read the encrypted text from the file
        const encryptedTextWithHash = await readFile('asymmetric_encrypted_text.txt');

        // Read the public key from the file
        const publicKey = await readFile('public_key.txt');

        // Perform asymmetric decryption logic
        const decryptedTextWithHash = decryptAsymmetric(encryptedTextWithHash, publicKey);

        // Separate the decrypted data and hash
        const decryptedData = decryptedTextWithHash.slice(0, -64); // Assuming SHA-256 hash (64 characters)
        const decryptedHash = decryptedTextWithHash.slice(-64);    // Assuming SHA-256 hash (64 characters)

        // Verify the integrity of the decrypted data
        const isIntegrityVerified = calculateHash(decryptedData) === decryptedHash;

        if (isIntegrityVerified) {
            // Save the decrypted text to a file
            await saveToFile('decrypted_text.txt', decryptedData);

            res.status(200).send('Asymmetric decryption and signature verification completed successfully');
        } else {
            res.status(400).send('Digital signature verification or data integrity check failed');
        }
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Endpoint for symmetric encryption


async function encryptAsymmetric(text) {
    // Generate key pair (public key and private key)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    // Use the public key to encrypt the content
    const encryptedText = crypto.privateEncrypt(privateKey, Buffer.from(text, 'utf-8')).toString('base64');

    return { encryptedText, publicKey, privateKey };
}

function decryptAsymmetric(encryptedText, publicKey) {
    // Perform asymmetric decryption logic
    // For demonstration purposes, using Node.js built-in crypto library
    return crypto.publicDecrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(encryptedText, 'base64')).toString('utf-8');
}

function verifySignature(data, signature, publicKey) {
    let verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(data);
    let result = verifier.verify(publicKey, signature, "base64");
    console.log(result)
    return result;
}


async function signText(text) {
    // Use the private key to create a digital signature
    const signature = crypto.sign('RSA-SHA256', Buffer.from(text, 'utf-8'), {
        key: await readFile('private_key.txt'),
        padding: crypto.constants.RSA_PKCS1_PADDING
    });

    return signature.toString('base64');
}

function calculateHash(text) {
    // Perform hash calculation logic (use a secure hashing library or algorithm)
    // For demonstration purposes, using Node.js built-in crypto library
    const hash = crypto.createHash('RSA-SHA256').update(text).digest('hex');
    return hash;
}


async function saveToFile(fileName, content) {
    const filePath = path.join(__dirname, fileName);
    await fs.writeFile(filePath, content);
    console.log(`${fileName} saved to ${filePath}`);
}

async function readFile(fileName) {
    const filePath = path.join(__dirname, fileName);
    return await fs.readFile(filePath, 'utf-8');
}

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

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

app.post('/symmetricEncryption', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        const symmetricKey = crypto.randomBytes(32);

        const iv = crypto.randomBytes(16);

        const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);

        const encryptedText = Buffer.concat([cipher.update(fileContent, 'utf-8'), cipher.final()]).toString('base64');

        await saveToFile('secret_key.txt', symmetricKey.toString('base64'));
        await saveToFile('symmetric_iv.txt', iv.toString('base64'));

        await saveToFile('symmetric_encrypted_text.txt', encryptedText);

        res.status(200).send('Symmetric encryption completed successfully');
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/symmetricDecryption', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        const encryptedText = await readFile('symmetric_encrypted_text.txt');

        const symmetricKey = Buffer.from(await readFile('secret_key.txt'), 'base64');
        const iv = Buffer.from(await readFile('symmetric_iv.txt'), 'base64');

        const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, iv);

        const decryptedText = Buffer.concat([decipher.update(Buffer.from(encryptedText, 'base64')), decipher.final()]).toString('utf-8');

        await saveToFile('symmetric_decrypted_text.txt', decryptedText);

        res.status(200).send('Symmetric decryption completed successfully');
    } catch (error) {
        console.error('Error processing file:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/asymmetricEncryption', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const fileContent = req.file.buffer.toString('utf-8');

        const hash = calculateHash(fileContent);

        const { encryptedText, publicKey, privateKey } = await encryptAsymmetric(fileContent + hash);
        await saveToFile('private_key.txt', privateKey);
        await saveToFile('public_key.txt', publicKey);
        await saveToFile('asymmetric_encrypted_text.txt', encryptedText);

        const signature = await signText(fileContent);

        await saveToFile('digital_signature.txt', signature);

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

        const encryptedTextWithHash = await readFile('asymmetric_encrypted_text.txt');

        const publicKey = await readFile('public_key.txt');

        const decryptedTextWithHash = decryptAsymmetric(encryptedTextWithHash, publicKey);

        const originalSignature = await readFile('digital_signature.txt');

        const decryptedData = decryptedTextWithHash.slice(0, -64);
        const decryptedHash = decryptedTextWithHash.slice(-64);

        const isHashValid = calculateHash(fileContent) === decryptedHash;
        const isSignatureValid = verifySignature(fileContent, originalSignature, publicKey)

        if (isHashValid && isSignatureValid) {
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


async function encryptAsymmetric(text) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    const encryptedText = crypto.privateEncrypt(privateKey, Buffer.from(text, 'utf-8')).toString('base64');

    return { encryptedText, publicKey, privateKey };
}

function decryptAsymmetric(encryptedText, publicKey) {
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
    const signature = crypto.sign('RSA-SHA256', Buffer.from(text, 'utf-8'), {
        key: await readFile('private_key.txt'),
        padding: crypto.constants.RSA_PKCS1_PADDING
    });

    return signature.toString('base64');
}

function calculateHash(text) {
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

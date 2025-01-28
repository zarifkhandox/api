const express = require('express');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const axios = require('axios');
const cors = require('cors');

const app = express();
const dbPath = process.env.DB_PATH || 'keys.db'; // Use environment variable for database path
const db = new sqlite3.Database(dbPath);

app.use(cors());
app.use(express.json());

app.all('/:apiUrl', (req, res) => {
    const apiUrl = `/${req.params.apiUrl}`;

    db.get(`SELECT encrypted_webhook, iv, key FROM keys WHERE api_url = ?`, [apiUrl], (err, row) => {
        if (err || !row) {
            console.error('API URL not found or database error:', err);
            return res.status(404).json({ error: 'API URL not found' });
        }

        const { encrypted_webhook, iv, key } = row;

        try {
            // Decrypt the webhook URL
            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
            let decrypted = decipher.update(encrypted_webhook, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            console.log('Decrypted webhook URL:', decrypted);

            // Forward the request to the decrypted webhook URL
            axios({
                method: 'POST',
                url: decrypted,
                headers: {
                    'Content-Type': 'application/json',
                },
                data: JSON.stringify({
                    content: req.body.content || 'Your API is now currently secure. This is used to check if your API is working.'
                })
            })
            .then(response => res.status(response.status).send(response.data))
            .catch(error => {
                console.error('Error forwarding request:', error.message);
                console.error('Response data:', error.response ? error.response.data : 'No response data');
                res.status(error.response ? error.response.status : 500).send(error.message);
            });
        } catch (decryptionError) {
            console.error('Decryption error:', decryptionError);
            res.status(500).json({ error: 'Failed to decrypt the webhook URL' });
        }
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`API server is running on http://localhost:${PORT}`);
});
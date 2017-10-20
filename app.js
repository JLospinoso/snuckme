"use strict";

const express = require("express");
const app = express();
const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware')
const NodeRSA = require("node-rsa");
const sslCertificate = require('get-ssl-certificate');
const AES = require("crypto-js/aes");
const cors = require('cors');

app.use(awsServerlessExpressMiddleware.eventContext());

const corsOptions = {
    origin: 'https://snuck.me'
};

const rsa = new NodeRSA(`-----BEGIN RSA PRIVATE KEY-----
YOUR PRIVATE KEY HERE
-----END RSA PRIVATE KEY-----`, {
    encryptionScheme: 'pkcs1'
});


app.get('/in/:opt', cors(corsOptions), function(req, res){
    try {
        const optionsJsonEncryptedEncoded = req.params.opt.replace(/\_/g, "/").replace(/\-/g, "+");
        const optionsJsonEncoded = rsa.decrypt(optionsJsonEncryptedEncoded, 'base64');
        const optionsJson = new Buffer(optionsJsonEncoded, 'base64').toString();
        const options = JSON.parse(optionsJson);
        const remoteUrl = options.url;
        const password = options.password;
        if(!password || !remoteUrl) {
            throw new Error("Bad input");
        }
        sslCertificate.get(remoteUrl)
                .then(function(certificate) {
                certificate.success = true;
                certificate.message = `Found certificate for ${remoteUrl}`;
                const plaintext = JSON.stringify(certificate);
                const ciphertext = AES.encrypt(plaintext, password).toString();
                res.status(200).send(ciphertext);
            }).catch(function(reason){
                const plaintext = JSON.stringify({
                    success: false,
                    message: `Unable to find certificate for ${remoteUrl}`
                });
                const ciphertext = AES.encrypt(plaintext, password).toString();
                res.status(200).send(ciphertext);
            });
    } catch (ex) {
        res.status(400).send();
    }
});

app.use('/', express.static('.'));

app.listen(8000);

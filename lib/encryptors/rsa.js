'use strict';

var crypto = require('crypto'),
    fs = require('fs'),
    path = require('path');

function encrypt(value, client) {
    var publicKey;
    if(client.publicKey) {
        publicKey = client.publicKey;
    } else {
        var absolutePath = path.resolve(client.relativeOrAbsolutePathToPublicKey);
        publicKey = fs.readFileSync(absolutePath, "utf8");
    }
    var buffer = new Buffer(value);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
}

function decrypt(value, client) {

    try {
        var privateKey;
        if(client.privateKey) {
            privateKey = client.privateKey;
        } else {
            var absolutePath = path.resolve(client.relativeOrAbsolutePathToPrivateKey);
            privateKey = fs.readFileSync(absolutePath, "utf8");
        }
        
        var buffer = new Buffer(value, "base64");
        var decrypted = crypto.privateDecrypt(privateKey, buffer);
        return decrypted.toString("utf8");
    }
    catch(err) {
        console.log('RSA authorization header decryption error: ' + err);
        return 'decoding error';
    }
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};
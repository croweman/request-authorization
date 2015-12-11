'use strict';

var crypto = require('crypto'),
    fs = require('fs'),
    path = require('path');

function encrypt(value, client) {

    var absolutePath = path.resolve(client.relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = new Buffer(value);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
}

function decrypt(value, client) {

    try {
        var absolutePath = path.resolve(client.relativeOrAbsolutePathToPrivateKey);
        var privateKey = fs.readFileSync(absolutePath, "utf8");
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
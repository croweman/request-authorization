var path = require('path'),
    fs = require('fs');

function SchemesBuilder() {

    this.availableEncryptors = [
        {
            name: 'HMAC-SHA256',
            path: './hashers/hmac-sha256',
            hasher: true
        },
        {
            name: 'HMAC-SHA512',
            path: './hashers/hmac-sha512',
            hasher: true
        },
        {
            name: 'HMAC-MD5',
            path: './hashers/hmac-md5',
            hasher: true
        },
        {
            name: 'RSA',
            path: './encryptors/rsa-public-key',
            hasher: false

        }
    ];
}

SchemesBuilder.prototype.build = function(schemes) {

    if (!(schemes instanceof Array)) {
        throw "authorizationSchemes variable must be an array";
    }

    if (schemes.length == 0) {
        throw "authorizationSchemes must be populated";
    }

    var validSchemes = [];

    for (var i = 0; i < schemes.length; i++) {

        var scheme = schemes[i];
        var schemeName = scheme.scheme;

        if (!schemeName || !(typeof schemeName === "string") || schemeName.length == 0)
            throw "scheme name has not been provided";

        var matchingHasher = undefined;
        var isHasher = false;

        for (var j = 0; j < this.availableEncryptors.length; j++) {

            if (this.availableEncryptors[j].name === schemeName) {
                matchingHasher = require(this.availableEncryptors[j].path);
                isHasher = this.availableEncryptors[j].hasher;
                break;
            }
        }

        if (!matchingHasher)
            throw "scheme name '" + schemeName + "' is not valid for a hasher or encryptor";

        scheme.isHasher = isHasher;

        validateScheme(scheme);

        if (isHasher) {
            scheme.hash = matchingHasher.hash;
        }
        else {
            scheme.encrypt = matchingHasher.encrypt;
            scheme.decrypt = matchingHasher.decrypt;
        }

        validSchemes.push(scheme);
    }

    return validSchemes;
}

function validateScheme(scheme) {
    validateTimestampData(scheme);
    validateClients(scheme);
}

function validateTimestampData(scheme) {
    if (typeof scheme.useTimestamp !== "undefined" && typeof scheme.useTimestamp !== 'boolean') {
        throw "useTimestamp must be a boolean";
    }

    if (scheme.useTimestamp && typeof scheme.timestampValidationWindowInSeconds !== "undefined" && typeof scheme.timestampValidationWindowInSeconds !== 'number') {
        throw "timestampValidationWindowInSeconds must be a number";
    }
};

function validateClients(scheme) {

    var clients = scheme.clients;

    if (!clients || clients.length == 0)
        throw "clients must be defined for scheme '" + scheme.scheme + "'";

    for (var i = 0; i < clients.length; i++) {

        var client = clients[i];
        var clientId = client.clientId;
        var password = client.password;
        var relativeOrAbsolutePathToPublicKey = client.relativeOrAbsolutePathToPublicKey;
        var relativeOrAbsolutePathToPrivateKey = client.relativeOrAbsolutePathToPrivateKey;

        if (!clientId || !(typeof clientId === "string") || clientId.length == 0)
            throw "clientId is invalid";

        if (scheme.isHasher) {

            if (!password || !(typeof password === "string") || password.length == 0) {
                throw "password is invalid";
            }
        }
        else {
            var publicKeyPathValid = (relativeOrAbsolutePathToPublicKey !== undefined && (typeof relativeOrAbsolutePathToPublicKey === "string") && relativeOrAbsolutePathToPublicKey.length > 0)

            if (publicKeyPathValid === true && !checkFileExists(relativeOrAbsolutePathToPublicKey))
                throw "relativeOrAbsolutePathToPublicKey file path does not exist";

            var privateKeyPathValid = (relativeOrAbsolutePathToPrivateKey !== undefined && (typeof relativeOrAbsolutePathToPrivateKey === "string") && relativeOrAbsolutePathToPrivateKey.length > 0)

            if (privateKeyPathValid === true && !checkFileExists(relativeOrAbsolutePathToPrivateKey))
                throw "relativeOrAbsolutePathToPrivateKey file path does not exist";

            if (!publicKeyPathValid && !privateKeyPathValid)
                throw "relativeOrAbsolutePathToPublicKey or relativeOrAbsolutePathToPrivateKey must be defined";
        }
    }
};

function checkFileExists(relativeOrAbsolutePath) {

    var absolutePath = path.resolve(relativeOrAbsolutePath);

    try
    {
        fs.statSync(absolutePath);
    }
    catch(err)
    {
        if(err.code == 'ENOENT')
            return false;
    }

    return true;
}

module.exports = new SchemesBuilder();
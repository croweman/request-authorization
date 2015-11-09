
this.availableEncryptors = [
    {
        name: 'HMAC-256',
        path: './encryption/hmac-256'
    }
];

function build(schemes) {

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

        var matchingEncryptor = undefined;

        for (var j = 0; j < this.availableEncryptors.length; j++) {

            if (this.availableEncryptors[j].name === schemeName) {
                matchingEncryptor = require(this.availableEncryptors[j].path);
                break;
            }
        }

        if (!matchingEncryptor)
            throw "scheme name '" + schemeName + "' is not valid for an encryptor";

        validateScheme(scheme);

        scheme.encrypt = matchingEncryptor.encrypt;

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

        if (!clientId || !(typeof clientId === "string") || clientId.length == 0)
            throw "clientId is invalid";

        if (!password || !(typeof password === "string") || password.length == 0)
            throw "password is invalid";
    }
};

module.exports = {
    availableEncryptors: this.availableEncryptors,
    build: build
};
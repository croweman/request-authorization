'use strict'

var schemesBuilder = require('./lib/schemes-builder'),
    parser = require('./lib/parser');

this.authorizationSchemes = [];

function init(schemes) {

    this.authorizationSchemes = schemesBuilder.build(schemes);
}

function generateAuthorizationHeader(options, data, timestampDate) {

    options = options || {};

    data = data || '';

    if (typeof data !== 'string') {
        throw 'data must be a string';
    }

    var scheme = findScheme(module.exports.authorizationSchemes, options.schemeName);
    var client = findClient(scheme, options.clientId);

    var timestamp = generateTimestamp(scheme, timestampDate);
    data = data + timestamp;
    var signature = scheme.hash(data, client);

    return scheme.scheme + " clientId=" + client.clientId + timestamp + ";signature=" + signature;
}

function isAuthorized(authorizationHeader, data, timestampDate) {

    var result = {
        result: false,
        schemeName: undefined,
        clientId: undefined,
        error: undefined
    };

    data = data || '';

    if (typeof data !== 'string') {
        result.error = 'data must be a string';
        return result;
    }

    var parsedHeader = parser.parseAuthorizationHeader(authorizationHeader);

    if (!parsedHeader) {
        result.error = 'Authorization header is invalid';
        return result;
    }

    var scheme;

    try {
        scheme = findScheme(module.exports.authorizationSchemes, parsedHeader.scheme);
    }
    catch (err) {
        result.error = err;
        return result;
    }

    result.schemeName = scheme.scheme;

    var client;

    try {
        client = findClient(scheme, parsedHeader.clientId);
    }
    catch (err) {
        result.error = err;
        return result;
    }

    result.clientId = client.clientId;

    if (!parsedHeader.signature || parsedHeader.signature.length == 0) {
        result.error = 'signature is invalid';
        return result;
    }

    if (scheme.useTimestamp && !parsedHeader.timestamp) {
        result.error = "timestamp is required";
        return result;
    }

    if (scheme.useTimestamp && new Date(parsedHeader.timestamp) == 'Invalid Date') {
        result.error = "timestamp is invalid";
        return result;
    }

    var timestamp = (scheme.useTimestamp ? generateTimestamp(scheme, new Date(parsedHeader.timestamp)) : '');
    data = data + timestamp;

    var signature = scheme.hash(data, client);

    if (parsedHeader.signature !== signature) {
        result.error = "Signatures do not match";
        return result;
    }

    if (scheme.useTimestamp && typeof scheme.timestampValidationWindowInSeconds !== "undefined" && typeof scheme.timestampValidationWindowInSeconds === 'number') {

        var differenceInSeconds = differenceBetweenDatesInSeconds(new Date(parsedHeader.timestamp), timestampDate || new Date());

        if (differenceInSeconds > scheme.timestampValidationWindowInSeconds) {
            result.error = "validation window has been breached";
            return result;
        }
    }

    result.result = true;

    return result;
}

function authorized(getDataFunc) {

    return function(req, res, next) {

        var data = '';

        if (getDataFunc)
            data = getDataFunc(req);

        var result = isAuthorized(req.headers['authorization'], data);

        req.requestAuthorizationIsAuthorizedResult = result;

        if (!result.result) {
            res.status(401).end();
            return;
        }

        next();
    };

}

function generateTimestamp(scheme, timestampDate) {

    var timestamp = '';

    if (scheme.useTimestamp) {
        timestampDate = timestampDate || new Date();
        timestamp = ';timestamp=' + timestampDate.toISOString();
    }

    return timestamp;
}

function findScheme(schemes, schemeName) {

    var matchingSchemes = schemes.filter(function(current) {
        return current.scheme === schemeName;
    });

    if (matchingSchemes.length == 0)
        throw "schemeName is not valid";

    return matchingSchemes[0];
}

function findClient(scheme, clientId) {

    var matchingClients = scheme.clients.filter(function(current) {
        return current.clientId === clientId;
    });

    if (matchingClients.length == 0)
        throw "clientId is not valid";

    return matchingClients[0];
}

function differenceBetweenDatesInSeconds(dateOne, dateTwo) {

    var dif = dateOne.getTime() - dateTwo.getTime();
    return Math.abs(dif / 1000);
}

module.exports = {
    authorizationSchemes: this.authorizationSchemes,
    init: init,
    generateAuthorizationHeader: generateAuthorizationHeader,
    isAuthorized: isAuthorized,
    authorized: authorized
};

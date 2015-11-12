'use strict';

var crypto = require('crypto');

function hash(value, client) {

    return crypto
        .createHmac('sha256', new Buffer(client.password, 'base64'))
        .update(value)
        .digest("base64");
}

module.exports = {
    hash: hash
};
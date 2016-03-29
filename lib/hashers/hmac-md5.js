'use strict';

var crypto = require('crypto');

function hash(value) {

    return crypto
        .createHash('md5')
        .update(value)
        .digest("base64");
}

module.exports = {
    hash: hash
};
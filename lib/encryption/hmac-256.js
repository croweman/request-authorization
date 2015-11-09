var crypto = require('crypto');

function encrypt(value, client) {

    var key = new Buffer(client.key, 'base64');

    return crypto
        .createHmac('sha256', key)
        .update(value)
        .digest("base64");
}

module.exports = {
    encrypt: encrypt
};
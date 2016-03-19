require('should');
var hasher = require('../../../../lib/hashers/hmac-sha512');

describe('HMAC-512 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'aGVsbG93b3JsZA==' });

        hash.should.eql('1l6xDJPmtZElZqTjogU5tFzRhQC09lanL/5vKlkoq74iGtgYk6fXzESprp4pMptjsezRIfklsbLSZ6M/mt0FPQ==');

    });
})
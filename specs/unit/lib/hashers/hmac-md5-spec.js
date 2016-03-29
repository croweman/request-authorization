require('should');
var hasher = require('../../../../lib/hashers/hmac-md5');

describe('md5 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'aGVsbG93b3JsZA==' });

        hash.should.eql('+2xzY7qJT7mQdgdgjn27TA==');

    });
})
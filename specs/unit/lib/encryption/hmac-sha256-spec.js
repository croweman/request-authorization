require('should');
var encryptor = require('../../../../lib/encryption/hmac-sha256');

describe('HMAC-256 lib', function() {

    it('correctly hashes a string', function() {

        var hash = encryptor.encrypt('TheValueToEncrypt', { password: 'abcdefghi=' });

        hash.should.eql('JJ0E6ey9ggRWs5+dokPxI1HXIwMQTVxF+DSXL43VCc8=');

    });
})
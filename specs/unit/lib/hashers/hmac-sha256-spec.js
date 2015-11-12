require('should');
var hasher = require('../../../../lib/hashers/hmac-sha256');

describe('HMAC-256 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'abcdefghi=' });

        hash.should.eql('JJ0E6ey9ggRWs5+dokPxI1HXIwMQTVxF+DSXL43VCc8=');

    });
})
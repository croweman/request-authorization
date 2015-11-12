require('should');
var hasher = require('../../../../lib/hashers/hmac-md5');

describe('md5 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'abcdefghi=' });

        hash.should.eql('fH8QhkGRhHxUdmZwjCUKBw==');

    });
})
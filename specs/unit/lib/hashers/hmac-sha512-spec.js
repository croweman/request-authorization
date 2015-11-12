require('should');
var hasher = require('../../../../lib/hashers/hmac-sha512');

describe('HMAC-512 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'abcdefghi=' });

        hash.should.eql('rEagks0PJOO6X7ytpmqvwSJDqns8390M/BnQlO5Cjz021tirvf16u0x6bo7t9hp08GVAcxJIlfUscRJn6XgPpw==');

    });
})
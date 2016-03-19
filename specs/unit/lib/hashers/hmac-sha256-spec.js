require('should');
var hasher = require('../../../../lib/hashers/hmac-sha256');

describe('HMAC-256 lib', function() {

    it('correctly hashes a string', function() {

        var hash = hasher.hash('TheValueToEncrypt', { password: 'aGVsbG93b3JsZA==' });

        hash.should.eql('j8l2ru3YrVfmCsfF51eIDw4RZ9gCh9Mm0KbSm5JfeJ0=');

    });
})
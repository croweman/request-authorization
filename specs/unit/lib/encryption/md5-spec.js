require('should');
var encryptor = require('../../../../lib/encryption/md5');

describe('md5 lib', function() {

    it('correctly hashes a string', function() {

        var hash = encryptor.encrypt('TheValueToEncrypt', { password: 'abcdefghi=' });

        hash.should.eql('fH8QhkGRhHxUdmZwjCUKBw==');

    });
})
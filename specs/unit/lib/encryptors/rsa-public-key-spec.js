require('should');
var encryptor = require('../../../../lib/encryptors/rsa');

describe('rsa public key lib', function() {

    it('correctly encrypts a string', function() {

        var val = encryptor.encrypt('TheValueToEncrypt', { relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem' });

        val.length.should.be.greaterThan(0);

    });

    it('correctly decrypts a string', function() {

        var val = encryptor.encrypt('TheValueToEncrypt', { relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem' });

        val.length.should.be.greaterThan(0);

        val = encryptor.decrypt(val, { relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key' })

        val.should.eql('TheValueToEncrypt');

    });
})
require('should');
var encryptor = require('../../../../lib/encryptors/rsa');

describe('rsa public key lib', function() {

    describe('using certificate files', function() {

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
    
    });

    describe('using certificate files', function() {

        var private;
        var public;

        beforeEach(function() {
            public = '-----BEGIN CERTIFICATE-----\n' +
                'MIIDtTCCAp2gAwIBAgIJAMKR/NsyfcazMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n' +
                'BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX\n' +
                'aWRnaXRzIFB0eSBMdGQwHhcNMTIxMTEyMjM0MzQxWhcNMTYxMjIxMjM0MzQxWjBF\n' +
                'MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50\n' +
                'ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n' +
                'CgKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN+H7GHp3/\n' +
                'QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXic78kOugM\n' +
                'Y1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6GbRKzyTKcB\n' +
                '58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRXkdDSHty6\n' +
                'lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1KkyHFqWpx\n' +
                'aJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABo4GnMIGkMB0GA1UdDgQWBBTs83nk\n' +
                'LtoXFlmBUts3EIxcVvkvcjB1BgNVHSMEbjBsgBTs83nkLtoXFlmBUts3EIxcVvkv\n' +
                'cqFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNV\n' +
                'BAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAMKR/NsyfcazMAwGA1UdEwQF\n' +
                'MAMBAf8wDQYJKoZIhvcNAQEFBQADggEBABw7w/5k4d5dVDgd/OOOmXdaaCIKvt7d\n' +
                '3ntlv1SSvAoKT8d8lt97Dm5RrmefBI13I2yivZg5bfTge4+vAV6VdLFdWeFp1b/F\n' +
                'OZkYUv6A8o5HW0OWQYVX26zIqBcG2Qrm3reiSl5BLvpj1WSpCsYvs5kaO4vFpMak\n' +
                '/ICgdZD+rxwxf8Vb/6fntKywWSLgwKH3mJ+Z0kRlpq1g1oieiOm1/gpZ35s0Yuor\n' +
                'XZba9ptfLCYSggg/qc3d3d0tbHplKYkwFm7f5ORGHDSD5SJm+gI7RPE+4bO8q79R\n' +
                'PAfbG1UGuJ0b/oigagciHhJp851SQRYf3JuNSc17BnK2L5IEtzjqr+Q=\n' +
                '-----END CERTIFICATE-----';
            private = '-----BEGIN RSA PRIVATE KEY-----\n' +
                'MIIEpAIBAAKCAQEAvtH4wKLYlIXZlfYQFJtXZVC3fD8XMarzwvb/fHUyJ6NvNStN\n' +
                '+H7GHp3/QhZbSaRyqK5hu5xXtFLgnI0QG8oE1NlXbczjH45LeHWhPIdc2uHSpzXi\n' +
                'c78kOugMY1vng4J10PF6+T2FNaiv0iXeIQq9xbwwPYpflViQyJnzGCIZ7VGan6Gb\n' +
                'RKzyTKcB58yx24pJq+CviLXEY52TIW1l5imcjGvLtlCp1za9qBZa4XGoVqHi1kRX\n' +
                'kdDSHty6lZWj3KxoRvTbiaBCH+75U7rifS6fR9lqjWE57bCGoz7+BBu9YmPKtI1K\n' +
                'kyHFqWpxaJc/AKf9xgg+UumeqVcirUmAsHJrMwIDAQABAoIBAQCYKw05YSNhXVPk\n' +
                'eHLeW/pXuwR3OkCexPrakOmwMC0s2vIF7mChN0d6hvhVlUp68X7V8SnS2JxAGo8v\n' +
                'iHY+Et3DdwZ3cxnzwh+BEhzgDfoIOmkoGppZPyX/K6klWtbGUrTtSISOWXbvEXQU\n' +
                'G0qGAvDOzIGTsdMDX7slnU70Ac23JybPY5qBSiE+ky8U4dm2fUHMroWub4QP5vA/\n' +
                'nqyWqX2FB/MEAbcujaknDQrFCtbmtUYlBbJCKGd9V3cGEqp6H7oH+ah2ofMc91gJ\n' +
                'mCHk3YyWZB/bcVXH3CA+s1ywvCOVDBZ3Nw7Pt9zIcv6Rl9UKIy+Nx0QjXxR90Hla\n' +
                'Tr0GHIShAoGBAPsD7uXm+0ksnGyKRYgvlVad8Z8FUFT6bf4B+vboDbx40FO8O/5V\n' +
                'PraBPC5z8YRSBOQ/WfccPQzakkA28F2pXlRpXu5JcErVWnyyUiKpX5sw6iPenQR2\n' +
                'JO9hY/GFbKiwUhVHpvWMcXFqFLSQu2A86jPnFFEfG48ZT4IhTzINKJVZAoGBAMKc\n' +
                'B3YGfVfY9qiRFXzYRdSRLg5c8p/HzuWwXc9vfJ4kQTDkPXe/+nqD67rzeT54uVec\n' +
                'jKoIrsCu4BfEaoyvOT+1KmUfdEpBgYZuuEC4CZf7dgKbXOpPVvZDMyJ/e7HyqTpw\n' +
                'mvIYJLPm2fNAcAsnbrNX5mhLwwzEIltbplUUeRdrAoGBAKhZgPYsLkhrZRXevreR\n' +
                'wkTvdUfD1pbHxtFfHqROCjhnhsFCM7JmFcNtdaFqHYczQxiZ7IqxI7jlNsVek2Md\n' +
                '3qgaa5LBKlDmOuP67N9WXUrGSaJ5ATIm0qrB1Lf9VlzktIiVH8L7yHHaRby8fQ8U\n' +
                'i7b3ukaV6HPW895A3M6iyJ8xAoGAInp4S+3MaTL0SFsj/nFmtcle6oaHKc3BlyoP\n' +
                'BMBQyMfNkPbu+PdXTjtvGTknouzKkX4X4cwWAec5ppxS8EffEa1sLGxNMxa19vZI\n' +
                'yJaShI21k7Ko3I5f7tNrDNKfPKCsYMEwgnHKluDwfktNTnyW/Uk2dgXuMaXSHHN5\n' +
                'XZt59K8CgYArGVOWK7LUmf3dkTIs3tXBm4/IMtUZmWmcP9C8Xe/Dg/IdQhK5CIx4\n' +
                'VXl8rgZNeX/5/4nJ8Q3LrdLau1Iz620trNRGU6sGMs3x4WQbSq93RRbFzfG1oK74\n' +
                'IOo5yIBxImQOSk5jz31gF9RJb15SDBIxonuWv8qAERyUfvrmEwR0kg==\n' +
                '-----END RSA PRIVATE KEY-----';
        })

        it('correctly encrypts a string', function() {

            var val = encryptor.encrypt('TheValueToEncrypt', { publicKey: public });

            val.length.should.be.greaterThan(0);

        });

        it('correctly decrypts a string', function() {

            var val = encryptor.encrypt('TheValueToEncrypt', { publicKey: public });
            console.log(val)

            val.length.should.be.greaterThan(0);

            val = encryptor.decrypt(val, { privateKey: private })

            val.should.eql('TheValueToEncrypt');

        });

    });
});
require('should');
var parser = require('../../../lib/parser');

describe('parser', function() {

    describe('generateAuthorizationObject', function() {

        it('correctly parses an authorization header into an object', function() {

            var header = 'HMAC-256 clientId=ClientA;timestamp=2015-11-05T08:30:24.195Z;signature=thesignature';

            var obj = parser.parseAuthorizationHeader(header);

            Object.keys(obj).length.should.eql(4);
            obj.scheme.should.eql('HMAC-256');
            obj.clientId.should.eql('ClientA');
            obj.timestamp.should.eql('2015-11-05T08:30:24.195Z');
            obj.signature.should.eql('thesignature');
        });

        it('returns undefined if the authorizationHeader is undefined', function() {

            var obj = parser.parseAuthorizationHeader(undefined);

            (!obj).should.be.true;

        });

        it('returns undefined if the authorizationHeader is null', function() {

            var obj = parser.parseAuthorizationHeader(null);

            (!obj).should.be.true;
        });

        it('returns undefined if the authorizationHeader is empty', function() {

            var obj = parser.parseAuthorizationHeader('');

            (!obj).should.be.true;
        });

        it('returns undefined if the authorizationHeader is just spaces', function() {

            var obj = parser.parseAuthorizationHeader(' ');

            (!obj).should.be.true;
        });

        it('returns undefined if the authorizationHeader contains just a scheme', function() {

            var obj = parser.parseAuthorizationHeader('HMAC-256');

            (!obj).should.be.true;
        });



    });

});
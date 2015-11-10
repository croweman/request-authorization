var nodeAuthorization = require('../../index');
var should = require('should');

describe('node-authorization', function() {

    it('Correctly caches schemes', function() {

        var schemes = [
            {
                scheme: 'HMAC-256',
                useTimestamp: true,
                clients: [
                    {
                        clientId: 'clientidone',
                        password: 'keyvalue'
                    }
                ]
            }
        ];

        nodeAuthorization.init(schemes);


        for (var i = 0; i < 10; i++) {

            nodeAuthorization = require('../../index');

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(true);
        }
    })

    describe('init', function() {

        beforeEach(function() {
            nodeAuthorization.authorizationSchemes = [];
        });

        it('correctly processes encryption data', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            nodeAuthorization.authorizationSchemes.length.should.eql(1);

            nodeAuthorization.authorizationSchemes[0].scheme.should.eql('HMAC-256');
            nodeAuthorization.authorizationSchemes[0].clients[0].clientId.should.eql('clientidone');
            nodeAuthorization.authorizationSchemes[0].clients[0].password.should.eql('keyvalue');

        });

    });

    describe('generateAuthorizationHeader', function() {

        beforeEach(function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                },
                {
                    scheme: 'HMAC-512',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                },
                {
                    scheme: 'MD5',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);
        });

        it('generates a valid authorization header when not providing any data', function() {

            var options = {
                schemeName: 'HMAC-256',
                clientId: 'clientidone'
            };

            var postData = undefined;

            var header = nodeAuthorization.generateAuthorizationHeader(options, postData);

            header.should.eql('HMAC-256 clientId=clientidone;signature=94H1WX7hHA9qjzH/yv3AgwzvRNTdudFYBCZW5BQMdGI=');
        });

        [
            { scheme: 'HMAC-256', signature: 'bLlSjEAgkfFtuAlFwr/0sjx1rPGg7tq1P8KszS0zz+g=' },
            { scheme: 'HMAC-512', signature: 'UaBRZz8cujFrtOxUqkRwOnu2RoYzVIpnndTga1MBCXPjQJgiiOMAkgi79HszsWtQXVFW/WHEzuemxvpIZqpW9Q==' },
            { scheme: 'MD5', signature: 'XSObr65DnzrAMK5vbMiBGA==' }
        ]
            .forEach(function(testCase) {

                it('generates a valid authorization header for scheme - ' + testCase.scheme, function() {

                    var options = {
                        schemeName: testCase.scheme,
                        clientId: 'clientidone'
                    };

                    var postData = 'Some data';

                    var header = nodeAuthorization.generateAuthorizationHeader(options, postData);

                    header.should.eql(testCase.scheme + ' clientId=clientidone;signature=' + testCase.signature);
                });

            });



        it('generates a valid authorization header when providing data and a timestamp', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var options = {
                schemeName: 'HMAC-256',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            var header = nodeAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));

            header.should.eql('HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=');
        });

        it('generates a valid authorization header when providing data and no timestamp', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var options = {
                schemeName: 'HMAC-256',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            var header = nodeAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));

            header.should.eql('HMAC-256 clientId=clientidone;signature=aizIhTj0/DYFzlYRPi7kD9A+2ArYlis2lFR3tobCqUw=');
        });

        it('will fail if an invalid schemeName option is provided', function(done) {

            var options = {
                schemeName: 'HMAC-2562',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            try {
                nodeAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));
            }
            catch(ex) {
                ex.should.eql('schemeName is not valid');
                done();
            }

        });

        it('will fail if an invalid clientId option is provided', function(done) {

            var options = {
                schemeName: 'HMAC-256',
                clientId: 'clientidtwo'
            };

            var postData = "{ firstName: 'john' }";

            try {
                nodeAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));
            }
            catch(ex) {
                ex.should.eql('clientId is not valid');
                done();
            }

        });

    });

    describe('isAuthorized', function() {

        beforeEach(function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);
        });

        it('returns true when header is valid and useTimestamp is enabled', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is enabled and timestamp falls within validity window', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: true,
                    timestampValidationWindowInSeconds: 10,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data, new Date('2015-11-05T12:12:37.675Z'));

            result.isAuthorized.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is not enabled', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;signature=aizIhTj0/DYFzlYRPi7kD9A+2ArYlis2lFR3tobCqUw=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(true);
        });

        it('returns false if scheme could not be found', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-258 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('schemeName is not valid');
        });

        it('returns false if client could not be found', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidtwo;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('clientId is not valid');
        });

        it('returns false if signature is not provided', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('signature is invalid');
        });

        it('returns false if signatures do not match', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5UA=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('Signatures do not match');
        });

        it('returns false if useTimestamp is enabled and timestamp not provided', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('timestamp is required');
        });

        it('returns false if useTimestamp is enabled and timestamp is an invalid date', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=asdf;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.isAuthorized.should.eql(false)
            result.error.should.eql('timestamp is invalid');
        });

        it('returns false if useTimestamp is enabled and timestamp does not fall within validity window', function() {

            var schemes = [
                {
                    scheme: 'HMAC-256',
                    useTimestamp: true,
                    timestampValidationWindowInSeconds: 10,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            nodeAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data, new Date('2015-11-05T12:12:46.675Z'));

            result.isAuthorized.should.eql(false);
            result.error.should.eql('validation window has been breached');
        });


    });

});


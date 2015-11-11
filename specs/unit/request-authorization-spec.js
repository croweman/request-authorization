var requestAuthorization = require('../../index');
var should = require('should');

describe('request-authorization', function() {

    it('Correctly caches schemes', function() {

        var schemes = [
            {
                scheme: 'HMAC-SHA256',
                useTimestamp: true,
                clients: [
                    {
                        clientId: 'clientidone',
                        password: 'keyvalue'
                    }
                ]
            }
        ];

        requestAuthorization.init(schemes);


        for (var i = 0; i < 10; i++) {

            nodeAuthorization = require('../../index');

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        }
    });

    describe('init', function() {

        beforeEach(function() {
            requestAuthorization.authorizationSchemes = [];
        });

        it('correctly processes encryption data', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            requestAuthorization.authorizationSchemes.length.should.eql(1);

            requestAuthorization.authorizationSchemes[0].scheme.should.eql('HMAC-SHA256');
            requestAuthorization.authorizationSchemes[0].clients[0].clientId.should.eql('clientidone');
            requestAuthorization.authorizationSchemes[0].clients[0].password.should.eql('keyvalue');

        });

    });

    describe('generateAuthorizationHeader', function() {

        beforeEach(function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                },
                {
                    scheme: 'HMAC-SHA512',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                },
                {
                    scheme: 'HMAC-MD5',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);
        });

        it('generates a valid authorization header when not providing any data', function() {

            var options = {
                schemeName: 'HMAC-SHA256',
                clientId: 'clientidone'
            };

            var postData = undefined;

            var header = requestAuthorization.generateAuthorizationHeader(options, postData);

            header.should.eql('HMAC-SHA256 clientId=clientidone;signature=94H1WX7hHA9qjzH/yv3AgwzvRNTdudFYBCZW5BQMdGI=');
        });

        [
            { scheme: 'HMAC-SHA256', signature: 'bLlSjEAgkfFtuAlFwr/0sjx1rPGg7tq1P8KszS0zz+g=' },
            { scheme: 'HMAC-SHA512', signature: 'UaBRZz8cujFrtOxUqkRwOnu2RoYzVIpnndTga1MBCXPjQJgiiOMAkgi79HszsWtQXVFW/WHEzuemxvpIZqpW9Q==' },
            { scheme: 'HMAC-MD5', signature: 'XSObr65DnzrAMK5vbMiBGA==' }
        ]
            .forEach(function(testCase) {

                it('generates a valid authorization header for scheme - ' + testCase.scheme, function() {

                    var options = {
                        schemeName: testCase.scheme,
                        clientId: 'clientidone'
                    };

                    var postData = 'Some data';

                    var header = requestAuthorization.generateAuthorizationHeader(options, postData);

                    header.should.eql(testCase.scheme + ' clientId=clientidone;signature=' + testCase.signature);
                });

            });



        it('generates a valid authorization header when providing data and a timestamp', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var options = {
                schemeName: 'HMAC-SHA256',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            var header = requestAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));

            header.should.eql('HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=');
        });

        it('generates a valid authorization header when providing data and no timestamp', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var options = {
                schemeName: 'HMAC-SHA256',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            var header = requestAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));

            header.should.eql('HMAC-SHA256 clientId=clientidone;signature=aizIhTj0/DYFzlYRPi7kD9A+2ArYlis2lFR3tobCqUw=');
        });

        it('will fail if an invalid schemeName option is provided', function(done) {

            var options = {
                schemeName: 'HMAC-SHA2562',
                clientId: 'clientidone'
            };

            var postData = "{ firstName: 'john' }";

            try {
                requestAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));
            }
            catch(ex) {
                ex.should.eql('schemeName is not valid');
                done();
            }

        });

        it('will fail if an invalid clientId option is provided', function(done) {

            var options = {
                schemeName: 'HMAC-SHA256',
                clientId: 'clientidtwo'
            };

            var postData = "{ firstName: 'john' }";

            try {
                requestAuthorization.generateAuthorizationHeader(options, postData, new Date('2015-11-05T12:12:35.675Z'));
            }
            catch(ex) {
                ex.should.eql('clientId is not valid');
                done();
            }

        });

        it('will fail if data is not a string', function(done) {

            var options = {
                schemeName: 'HMAC-SHA256',
                clientId: 'clientidone'
            };

            try {
                requestAuthorization.generateAuthorizationHeader(options, {}, new Date('2015-11-05T12:12:35.675Z'));
            }
            catch(ex) {
                ex.should.eql('data must be a string');
                done();
            }

        });

    });

    describe('isAuthorized', function() {

        beforeEach(function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);
        });

        it('returns true when header is valid and useTimestamp is enabled', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is enabled and timestamp falls within validity window', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
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

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data, new Date('2015-11-05T12:12:37.675Z'));

            result.result.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is not enabled', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;signature=aizIhTj0/DYFzlYRPi7kD9A+2ArYlis2lFR3tobCqUw=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        });

        it('returns false if scheme could not be found', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA258 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('schemeName is not valid');
        });

        it('returns false if client could not be found', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidtwo;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('clientId is not valid');
        });

        it('returns false if signature is not provided', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('signature is invalid');
        });

        it('returns false if signatures do not match', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5UA=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('Signatures do not match');
        });

        it('returns false if useTimestamp is enabled and timestamp not provided', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('timestamp is required');
        });

        it('returns false if useTimestamp is enabled and timestamp is an invalid date', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=asdf;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('timestamp is invalid');
        });

        it('returns false if useTimestamp is enabled and timestamp does not fall within validity window', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
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

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data, new Date('2015-11-05T12:12:46.675Z'));

            result.result.should.eql(false);
            result.error.should.eql('validation window has been breached');
        });

        it('returns false when data is not a valid string', function() {

            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, {});

            result.result.should.eql(false);
            result.error.should.eql('data must be a string');
        });

    });

    describe('authorized', function() {

        beforeEach(function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);
        });

        it('should call the callback if user is authorized', function(done) {

            function getDataFunc(req) {

                return req.params.id + JSON.stringify(req.body);
            }

            var callback = function() {
                done();
            }

            var req = {
                headers: [],
                params: {
                    id: '123456'
                },
                body: {
                firstName: 'joe'
                }
            };
            req.headers['authorization'] = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=Kk8HHaCG2hGCV+u6uk37qpIoC7GPuuu1we6xOsh7VvQ=';

            requestAuthorization.authorized(getDataFunc)(req, undefined, callback);

        });

        it('should send a 401 error response is the user is not authorized', function(done) {

            function getDataFunc(req) {

                return req.params.id + JSON.stringify(req.body);
            }

            var callback = function() {
                done('should not have called the callback');
            }

            var req = {
                headers: [],
                params: {
                    id: '123456'
                },
                body: {
                    firstName: 'joe'
                }
            };

            req.headers['authorization'] = 'HMAC-SHA256-Invalid clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=Kk8HHaCG2hGCV+u6uk37qpIoC7GPuuu1we6xOsh7VvQ=';

            var status;
            var endCalled;

            var res = {
                status: function(statusCode) {
                    status = statusCode;
                    return {
                        end: function() {
                            endCalled = true;
                        }
                    }
                }
            }

            requestAuthorization.authorized(getDataFunc)(req, res, callback);

            status.should.eql(401)
            endCalled.should.be.true;
            done();
        });

    });

});


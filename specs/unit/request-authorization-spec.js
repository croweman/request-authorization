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
                        password: 'aGVsbG93b3JsZA=='
                    }
                ]
            }
        ];

        requestAuthorization.init(schemes);


        for (var i = 0; i < 10; i++) {

            nodeAuthorization = require('../../index');

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=';

            var result = nodeAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        }
    });

    describe('init', function() {

        beforeEach(function() {
            requestAuthorization.authorizationSchemes = [];
        });

        it('correctly processes hashers data', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                },
                {
                    scheme: 'RSA',
                    useTimestamp: true,
                    timestampValidationWindowInSeconds: 60,
                    clients: [
                        {
                            clientId: 'clientidtwo',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            requestAuthorization.authorizationSchemes.length.should.eql(2);

            requestAuthorization.authorizationSchemes[0].scheme.should.eql('HMAC-SHA256');
            requestAuthorization.authorizationSchemes[0].clients[0].clientId.should.eql('clientidone');
            requestAuthorization.authorizationSchemes[0].clients[0].password.should.eql('aGVsbG93b3JsZA==');

            requestAuthorization.authorizationSchemes[1].scheme.should.eql('RSA');
            requestAuthorization.authorizationSchemes[1].clients[0].clientId.should.eql('clientidtwo');
            requestAuthorization.authorizationSchemes[1].clients[0].relativeOrAbsolutePathToPublicKey.should.eql('./specs/unit/lib/encryptors/public.pem');
            requestAuthorization.authorizationSchemes[1].clients[0].relativeOrAbsolutePathToPrivateKey.should.eql('./specs/unit/lib/encryptors/private.key');

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
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                },
                {
                    scheme: 'HMAC-SHA512',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                },
                {
                    scheme: 'HMAC-MD5',
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                },
                {
                    scheme: 'RSA',
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
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

            header.should.eql('HMAC-SHA256 clientId=clientidone;signature=mHdt4fYvmvxKWlFTJjjaD4cNU4IEJK+VmQhZCsaxtLE=');
        });

        it('throws a file path error if RSA scheme is being used and public key file path is invalid', function() {

            var options = {
                schemeName: 'RSA',
                clientId: 'clientidone'
            };

            var schemes = [
                {
                    scheme: 'RSA',
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var postData = '{}';

            try {
                requestAuthorization.generateAuthorizationHeader(options, postData);
            }
            catch (err) {
                err.should.eql('relativeOrAbsolutePathToPublicKey is invalid')
            }
        });

        [
            { scheme: 'HMAC-SHA256', signature: '8L3+crNYRiafj2V2R3knjYSAUOsMrp5hShOTGh+tP/s=' },
            { scheme: 'HMAC-SHA512', signature: 'M/JeTbTtT3bo/kYAgIcZEGVeyJ9WsLj8up4Gg0QS5QtA3dauxWRMwaNuxW1+sLxi6RMOJlTpJiR70bc+5PAAQw==' },
            { scheme: 'HMAC-MD5', signature: 'W4L4v03yv7DmbMqnMG/QJA==' },
            { scheme: 'RSA', encryptor: true }
        ]
            .forEach(function(testCase) {

                it('generates a valid authorization header for scheme - ' + testCase.scheme, function() {

                    var options = {
                        schemeName: testCase.scheme,
                        clientId: 'clientidone'
                    };

                    var postData = 'Some data';

                    var header = requestAuthorization.generateAuthorizationHeader(options, postData);

                    var encryptor = (testCase.encryptor !== undefined && testCase.encryptor === true);

                    if (!encryptor) {
                        header.should.eql(testCase.scheme + ' clientId=clientidone;signature=' + testCase.signature);
                    }
                    else {
                        var prefix = testCase.scheme + ' clientId=clientidone;signature=';
                        header.substr(0, prefix.length).should.eql(prefix);
                        header.length.should.be.greaterThan(prefix.length);
                    }
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
                            password: 'aGVsbG93b3JsZA=='
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

            header.should.eql('HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=');
        });

        it('generates a valid authorization header when providing data and no timestamp', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
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

            header.should.eql('HMAC-SHA256 clientId=clientidone;signature=gnH88cA/CNpAF2753f14IlPP3D9ZabChB0i1x3lm/yo=');
        });

        it('generates a valid authorization header when providing data and an using an alias', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    alias: 'alias-one',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
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

            header.should.eql('alias-one clientId=clientidone;signature=gnH88cA/CNpAF2753f14IlPP3D9ZabChB0i1x3lm/yo=');
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
                ex.should.eql('schemeName is not valid, has the request-authorization.init should be called or an invalid schemeName has been used');
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
                    alias: 'alias-one',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                },
                {
                    scheme: 'RSA',
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);
        });

        it('returns true when header is valid and valid alias is defined and useTimestamp is enabled', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'alias-one clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
            (!result.error).should.eql(true);
            result.schemeName.should.eql('HMAC-SHA256');
            result.clientId.should.eql('clientidone');
        });

        it('returns true when header is valid and useTimestamp is enabled', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
            (!result.error).should.eql(true);
            result.schemeName.should.eql('HMAC-SHA256');
            result.clientId.should.eql('clientidone');
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
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data, new Date('2015-11-05T12:12:37.675Z'));

            result.result.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is not enabled - hashing', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;signature=gnH88cA/CNpAF2753f14IlPP3D9ZabChB0i1x3lm/yo=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        });

        it('returns true when header is valid and useTimestamp is not enabled - encryption', function() {

            var schemes = [
                {
                    scheme: 'RSA',
                    useTimestamp: false,
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'RSA clientId=clientidone;signature=nhWW4ZNUiTIP+FhlwKSYOuyg+4jk/gmqi6ubS6pL/X+qV2FtnneJY+WUhi8Y4fGXTJ18KN7FfK3b/oLhd2fF+GvsRMJ+2dvj8/D99hAkGWFZ+OSgQuO4PABO11X8sQYrIw0HaGGH5okWs397ujfpOHR76J2Fhfq49sOZDN29wHSJJZMooLPkgCzJA1UT43UAaZiSFAZgLMoAlTDazC69EAPTUhWvuvJtOgMiGq73evdl5my8PbKtNGqDVkcPUpwywYD4VLLgWV2M46iDGwN/7knt0R3+zmdxfrVmjnVeqy/uBrYQzS/J/x7tzsa+c7lVyKh97sLOPEWfn6t8NfO3gw==';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(true);
        });

        it('returns false if scheme could not be found', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA258 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('schemeName is not valid, has the request-authorization.init should be called or an invalid schemeName has been used');
        });

        it('returns false if client could not be found', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    useTimestamp: true,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'aGVsbG93b3JsZA=='
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

        it('returns false if signatures do not match - hashing', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5UA=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('Signatures do not match');
        });

        it('returns false if signature is invalid - encryption', function() {

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'RSA clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5UA=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('decrypted data does not match data');
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
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=llDypaKbzCXLwt5kK72PkngpPintxoWvavPazFYgh8Q=';

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

        it('returns false if relativeOrAbsolutePathToPrivateKey is not defined - encryption', function() {

            var schemes = [
                {
                    scheme: 'RSA',
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem'
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);

            var data = "{ firstName: 'john' }";
            var authorizationHeader = 'RSA clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5UA=';

            var result = requestAuthorization.isAuthorized(authorizationHeader, data);

            result.result.should.eql(false)
            result.error.should.eql('relativeOrAbsolutePathToPrivateKey is invalid');
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
                            password: 'aGVsbG93b3JsZA=='
                        }
                    ]
                }
            ];

            requestAuthorization.init(schemes);
        });

        it('should call the callback if user is authorized and getData function supplied', function(done) {

            function getDataFunc(req) {

                return req.params.id + JSON.stringify(req.body);
            }

            var callback = function() {
                req.requestAuthorizationIsAuthorizedResult.result.should.eql(true);
                req.requestAuthorizationIsAuthorizedResult.schemeName.should.eql('HMAC-SHA256');
                req.requestAuthorizationIsAuthorizedResult.clientId.should.eql('clientidone');
                (!req.requestAuthorizationIsAuthorizedResult.error).should.eql(true);
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
            req.headers['authorization'] = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=QGis/ehV9dy65xcvE3lwMiLj9Ah9Ew49XdM5Y+pGSaM=';

            requestAuthorization.authorized(getDataFunc)(req, undefined, callback);

        });

        it('should call the callback if user is authorized and getData function is not supplied', function(done) {

            var callback = function() {
                req.requestAuthorizationIsAuthorizedResult.result.should.eql(true);
                req.requestAuthorizationIsAuthorizedResult.schemeName.should.eql('HMAC-SHA256');
                req.requestAuthorizationIsAuthorizedResult.clientId.should.eql('clientidone');
                (!req.requestAuthorizationIsAuthorizedResult.error).should.eql(true);
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
            req.headers['authorization'] = 'HMAC-SHA256 clientId=clientidone;timestamp=2015-11-05T12:12:35.675Z;signature=To8nSBu1PylzYmy3b7UIXhztlgeurghC9mAkjrLjDFE=';

            requestAuthorization.authorized()(req, undefined, callback);

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

            req.requestAuthorizationIsAuthorizedResult.result.should.eql(false);
            (!req.requestAuthorizationIsAuthorizedResult.schemeName).should.eql(true);
            (!req.requestAuthorizationIsAuthorizedResult.clientId).should.eql(true);
            req.requestAuthorizationIsAuthorizedResult.error.should.eql('schemeName is not valid, has the request-authorization.init should be called or an invalid schemeName has been used');

            done();
        });

    });

});


var schemesBuilder = require('../../../lib/schemes-builder');
var should = require('should');

describe('schemesBuilder', function() {

    describe('build', function() {

        it('correctly processes hashers data', function() {

            var schemes = [
                {
                    scheme: 'HMAC-SHA256',
                    alias: 'BLAH-123',
                    useTimestamp: true,
                    timestampValidationWindowInSeconds: 60,
                    clients: [
                        {
                            clientId: 'clientidone',
                            password: 'keyvalue'
                        }
                    ]
                }
            ];

            var validSchemes = schemesBuilder.build(schemes);

            validSchemes.length.should.eql(1);

            validSchemes[0].scheme.should.eql('HMAC-SHA256');
            validSchemes[0].alias.should.eql('BLAH-123');
            validSchemes[0].useTimestamp.should.eql(true);
            validSchemes[0].timestampValidationWindowInSeconds.should.eql(60);
            validSchemes[0].clients.length.should.eql(1);
            validSchemes[0].clients[0].clientId.should.eql('clientidone');
            validSchemes[0].clients[0].password.should.eql('keyvalue');
            (validSchemes[0].hash !== undefined).should.eql(true);
            (validSchemes[0].encrypt == undefined).should.eql(true);
            (validSchemes[0].decrypt == undefined).should.eql(true);

        });

        it('correctly processes encryptors data', function() {

            var schemes = [
                {
                    scheme: 'RSA',
                    useTimestamp: true,
                    timestampValidationWindowInSeconds: 60,
                    clients: [
                        {
                            clientId: 'clientidone',
                            relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                            relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                        }
                    ]
                }
            ];

            var validSchemes = schemesBuilder.build(schemes);

            validSchemes.length.should.eql(1);

            validSchemes[0].scheme.should.eql('RSA');
            validSchemes[0].useTimestamp.should.eql(true);
            validSchemes[0].timestampValidationWindowInSeconds.should.eql(60);
            validSchemes[0].clients.length.should.eql(1);
            validSchemes[0].clients[0].clientId.should.eql('clientidone');
            (validSchemes[0].hash === undefined).should.eql(true);
            (validSchemes[0].encrypt != undefined).should.eql(true);
            (validSchemes[0].decrypt != undefined).should.eql(true);
            validSchemes[0].clients[0].relativeOrAbsolutePathToPublicKey.should.eql('./specs/unit/lib/encryptors/public.pem');
            validSchemes[0].clients[0].relativeOrAbsolutePathToPrivateKey.should.eql('./specs/unit/lib/encryptors/private.key');

        });

        it('will fail if no hashers are provided', function(done) {

            try {
                schemesBuilder.build(undefined);
            }
            catch (err) {
                err.should.eql('authorizationSchemes variable must be an array');
                done();
            };

        });

        it('will fail if an empty scheme array is provided', function(done) {

            try {
                schemesBuilder.build([]);
            }
            catch (err) {
                err.should.eql('authorizationSchemes must be populated');
                done();
            };
        });

        it('will fail if an invalid scheme is provided', function(done) {

            try {
                schemesBuilder.build([{
                    scheme: 'testScheme'
                }]);
            }
            catch (err) {
                err.should.eql("scheme name 'testScheme' is not valid for a hasher or encryptor");
                done();
            };
        });

        [
            {
                scheme: '',
            },
            {
                scheme: undefined,
            },
            {
                scheme: [],
            }
        ].forEach(function(scheme) {

                it('will fail if an invalid scheme name is provided', function(done) {

                    try {
                        schemesBuilder.build([scheme]);
                    }
                    catch (err) {
                        err.should.eql("scheme name has not been provided");
                        done();
                    };
                });

            });

        [
            {
                scheme: 'HMAC-SHA256',
                alias: ''
            },
            {
                scheme: 'HMAC-SHA256',
                alias: []
            }
        ].forEach(function(scheme) {

                it('will fail if an invalid alias name is provided', function(done) {

                    try {
                        schemesBuilder.build([scheme]);
                    }
                    catch (err) {
                        err.should.eql("invalid alias name has been provided");
                        done();
                    };
                });

            });

        describe('HMAC-SHA256 scheme', function() {

            it('will be created if data is valid', function() {

                var schemes = [
                    {
                        scheme: 'HMAC-SHA256',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 60,
                        clients: [
                            {
                                clientId: 'clientidone',
                                password: 'keyvalue'
                            }
                        ]
                    }
                ];

                var validSchemes = schemesBuilder.build(schemes);

                validSchemes[0].scheme.should.eql('HMAC-SHA256');
                (validSchemes[0].hash !== undefined).should.eql(true);
                (validSchemes[0].encrypt == undefined).should.eql(true);
                (validSchemes[0].decrypt == undefined).should.eql(true);
            });

            it('will be created if useTimestamp is not defined', function() {
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

                var validSchemes = schemesBuilder.build(schemes);

                validSchemes[0].scheme.should.eql('HMAC-SHA256');
            });

            it('will fail if an invalid boolean value is provided for useTimestamp', function(done) {

                var schemes = [
                    {
                        scheme: 'HMAC-SHA256',
                        useTimestamp: 'asdf',
                        timestampValidationWindowInSeconds: 'adsf',
                        clients: [
                            {
                                clientId: 'clientidone',
                                password: 'keyvalue'
                            }
                        ]
                    }
                ];

                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("useTimestamp must be a boolean");
                    done();
                };
            });

            it('will fail if an invalid number value is provided for timestampValidationWindowInSeconds when useTimestamp is enabled', function(done) {

                var schemes = [
                    {
                        scheme: 'HMAC-SHA256',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds:'asdf',
                        clients: [
                            {
                                clientId: 'clientidone',
                                password: 'keyvalue'
                            }
                        ]
                    }
                ];

                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("timestampValidationWindowInSeconds must be a number");
                    done();
                };

            });

            it('will fail if no clients are defined', function(done) {

                var schemes = [
                    {
                        scheme: 'HMAC-SHA256',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 60,
                    }
                ];

                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("clients must be defined for scheme 'HMAC-SHA256'");
                    done();
                };
            });

            it('will fail if clients are empty', function(done) {

                var schemes = [
                    {
                        scheme: 'HMAC-SHA256',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds:60,
                        clients: []
                    }
                ];

                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("clients must be defined for scheme 'HMAC-SHA256'");
                    done();
                };
            });

            [
                undefined,
                1,
                ''
            ].forEach(function(clientId) {

                it('will fail if an invalid clientId is defined', function(done) {

                    var schemes = [
                        {
                            scheme: 'HMAC-SHA256',
                            useTimestamp: true,
                            timestampValidationWindowInSeconds: 60,
                            clients: [
                                {
                                    clientId: clientId,
                                    password: 'keyvalue'
                                }
                            ]
                        }
                    ];

                    try {
                        schemesBuilder.build(schemes);
                    }
                    catch (err) {
                        err.should.eql("clientId is invalid");
                        done();
                    };

                });

            });

            [
                undefined,
                1,
                ''
            ].forEach(function(key) {

                it('will fail if an invalid client password is defined', function(done) {

                    var schemes = [
                        {
                            scheme: 'HMAC-SHA256',
                            useTimestamp: true,
                            timestampValidationWindowInSeconds: 60,
                            clients: [
                                {
                                    clientId: 'ClientA',
                                    password: key
                                }
                            ]
                        }
                    ];

                    try {
                        schemesBuilder.build(schemes);
                    }
                    catch (err) {
                        err.should.eql("password is invalid");
                        done();
                    };

                });

            });

        });

        describe('RSA scheme', function() {

            it('will be created if data is valid', function() {

                var schemes = [
                    {
                        scheme: 'RSA',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 60,
                        clients: [
                            {
                                clientId: 'clientidone',
                                relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                                relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                            }
                        ]
                    }
                ];

                var validSchemes = schemesBuilder.build(schemes);

                validSchemes[0].scheme.should.eql('RSA');
                (validSchemes[0].hash === undefined).should.eql(true);
                (validSchemes[0].encrypt != undefined).should.eql(true);
                (validSchemes[0].decrypt != undefined).should.eql(true);
                validSchemes[0].clients[0].relativeOrAbsolutePathToPublicKey.should.eql('./specs/unit/lib/encryptors/public.pem');
                validSchemes[0].clients[0].relativeOrAbsolutePathToPrivateKey.should.eql('./specs/unit/lib/encryptors/private.key');
            });

            it('will be created if useTimestamp is not defined', function() {
                var schemes = [
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


                var validSchemes = schemesBuilder.build(schemes);

                validSchemes[0].scheme.should.eql('RSA');
            });

            it('will fail if an invalid boolean value is provided for useTimestamp', function(done) {

                var schemes = [
                    {
                        scheme: 'RSA',
                        useTimestamp: 'asdf',
                        timestampValidationWindowInSeconds: 'asdf',
                        clients: [
                            {
                                clientId: 'clientidone',
                                relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                                relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                            }
                        ]
                    }
                ];


                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("useTimestamp must be a boolean");
                    done();
                };
            });

            it('will fail if an invalid number value is provided for timestampValidationWindowInSeconds when useTimestamp is enabled', function(done) {

                var schemes = [
                    {
                        scheme: 'RSA',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 'asdf',
                        clients: [
                            {
                                clientId: 'clientidone',
                                relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                                relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                            }
                        ]
                    }
                ];


                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("timestampValidationWindowInSeconds must be a number");
                    done();
                };

            });

            it('will fail if no clients are defined', function(done) {

                var schemes = [
                    {
                        scheme: 'RSA',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 60
                    }
                ];


                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("clients must be defined for scheme 'RSA'");
                    done();
                };
            });

            it('will fail if clients are empty', function(done) {

                var schemes = [
                    {
                        scheme: 'RSA',
                        useTimestamp: true,
                        timestampValidationWindowInSeconds: 60,
                        clients: []
                    }
                ];


                try {
                    schemesBuilder.build(schemes);
                }
                catch (err) {
                    err.should.eql("clients must be defined for scheme 'RSA'");
                    done();
                };
            });

            [
                undefined,
                1,
                ''
            ].forEach(function(clientId) {

                    it('will fail if an invalid clientId is defined', function(done) {

                        var schemes = [
                            {
                                scheme: 'RSA',
                                useTimestamp: true,
                                timestampValidationWindowInSeconds: 60,
                                clients: [
                                    {
                                        clientId: clientId,
                                        relativeOrAbsolutePathToPublicKey: './specs/unit/lib/encryptors/public.pem',
                                        relativeOrAbsolutePathToPrivateKey: './specs/unit/lib/encryptors/private.key'
                                    }
                                ]
                            }
                        ];


                        try {
                            schemesBuilder.build(schemes);
                        }
                        catch (err) {
                            err.should.eql("clientId is invalid");
                            done();
                        };

                    });

                });

            [
                undefined,
                1,
                ''
            ].forEach(function(val) {

                    it('will fail if an invalid client relativeOrAbsolutePathToPublicKey and invalid client relativeOrAbsolutePathToPrivateKey is defined', function(done) {

                        var schemes = [
                            {
                                scheme: 'RSA',
                                useTimestamp: true,
                                timestampValidationWindowInSeconds: 60,
                                clients: [
                                    {
                                        clientId: 'clientidone',
                                        relativeOrAbsolutePathToPublicKey: val,
                                        relativeOrAbsolutePathToPrivateKey: val
                                    }
                                ]
                            }
                        ];


                        try {
                            schemesBuilder.build(schemes);
                        }
                        catch (err) {
                            err.should.eql("relativeOrAbsolutePathToPublicKey or relativeOrAbsolutePathToPrivateKey must be defined");
                            done();
                        };

                    });

                });

        });

    });
});



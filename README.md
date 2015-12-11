# request-authorization

[![build status](https://travis-ci.org/croweman/request-authorization.svg)](https://travis-ci.org/croweman/request-authorization) [![npm version](https://badge.fury.io/js/request-authorization.svg)](https://www.npmjs.com/package/request-authorization)


Node module for signing and authorizing requests.

crypto.publicEncrypt(public_key, buffer)
document how to use this!!!
https://nodejs.org/api/crypto.html#crypto_certificate_verifyspkac_spkac
Encrypts buffer with public_key. Only RSA is currently supported.

public_key can be an object or a string. If public_key is a string, it is treated as the key with no passphrase and will use RSA_PKCS1_OAEP_PADDING. Since RSA public keys may be derived from private keys you may pass a private key to this method.

public_key:

key : A string holding the PEM encoded private key
passphrase : An optional string of passphrase for the private key
padding : An optional padding value, one of the following:
constants.RSA_NO_PADDING
constants.RSA_PKCS1_PADDING
constants.RSA_PKCS1_OAEP_PADDING
NOTE: All paddings are defined in constants module.

var crypto = require("crypto");
var path = require("path");
var fs = require("fs");

var encryptStringWithRsaPublicKey = function(toEncrypt, relativeOrAbsolutePathToPublicKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = new Buffer(toEncrypt);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
};

var decryptStringWithRsaPrivateKey = function(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey);
    var privateKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = new Buffer(toDecrypt, "base64");
    var decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
    });
};

module.exports = {
    encryptStringWithRsaPublicKey: encryptStringWithRsaPublicKey,
    decryptStringWithRsaPrivateKey: decryptStringWithRsaPrivateKey
}





## Usage

Firstly the module will need to be initialized with schemes and there associated clients.  This only needs to be done once preferably on application start.

```js

var requestAuthorization = require('request-authorization');

var schemes = [
    {
        scheme: 'HMAC-SHA256',
        useTimestamp: true,
        clients: [
            {
                clientId: 'clientOne',
                password: 'p455w0rd'
            }
        ]
    }
];

requestAuthorization.init(schemes);

```

## Generate authororization header

The generateAuthorizationHeader function can be used to generate authorization headers.  The function accepts an options argument and data as a string to be used for the signature.

```js
var requestAuthorization = require('request-authorization');

var options = {
    schemeName: 'HMAC-SHA256',
    clientId: 'clientOne'
};

var data = req.params.userId + JSON.stringify(req.body);
var header = requestAuthorization.generateAuthorizationHeader(options, data);
```

The generated authorization header would look like the following:

```js
HMAC-SHA256 clientId=clientOne;timestamp=2015-11-11T13:41:09.430Z;signature=cCqTvX6CZDv1N00QUP1lsvzSO6SFawQHz1bTHCeBnyA=
```

## isAuthorized

The isAuthorized function can be used to authorize a request.  The function accepts the 'authorization' header and request data as a string.

```js
var requestAuthorization = require('request-authorization');

var data = "{ firstName: 'john' }";
var authorizationHeader = 'HMAC-SHA256 clientId=clientOne;timestamp=2015-11-05T12:12:35.675Z;signature=8+OIZQiZBqdBx5CGzVyMMfNhXPbhz2szJX2WqWrun5U=';

var authorized = requestAuthorization.isAuthorized(authorizationHeader, data);

console.log('authorization scheme name:', authorized.schemeName);
console.log('authorization client id:', authorized.clientId);

if (authorized.result) {
    console.log('You are allowed in');
}
else {
    console.log('Denied');
    console.log('authorization error', authorized.error);
}
```
## authorization

Express authorization middleware is available and can be used in the following way.

```js
var requestAuthorization = require('request-authorization');
var express = require('express');
var router = express.Router();

router.get('/', requestAuthorization.authorized(getData), function(req, res) {
	res.status(200).send('You got in');

	console.log(req.requestAuthorizationIsAuthorizedResult.schemeName);
	console.log(req.requestAuthorizationIsAuthorizedResult.clientId);
	console.log(req.requestAuthorizationIsAuthorizedResult.result);
	console.log(req.requestAuthorizationIsAuthorizedResult.error);
});

function getData(req) {
    return req.params.id + JSON.stringify(req.body);
}

// a route could also be used that does not make use of a get data function
router.get('/', requestAuthorization.authorized(), function(req, res) {
	res.status(200).send('You got in');
});
```

## Scheme options

When initialising the module multiple schemes can be provided, each scheme can also have multiple clients each having different names and passwords for for signature generation.

The schemes currently available are:

- HMAC-SHA256
- HMAC-SHA512
- HMAC-MD5

### useTimestamp

If the userTimestamp option is defined and set to true the iso string date format will be used in the signature and header.

```js
var headerExapmle = 'HMAC-SHA256 clientId=clientOne;timestamp=2015-11-11T13:41:09.430Z;signature=cCqTvX6CZDv1N00QUP1lsvzSO6SFawQHz1bTHCeBnyA='

var isoFormatDate = new Date().toISOString();
```

### timestampValidationWindowInSeconds

If useTimestamp is defined and the timestampValidationWindowInSeconds is defined then the difference between the timestamp and the server dateTime will be checked and if it is outside of the configured window the request would not be authorized.

```js
var requestAuthorization = require('request-authorization');

var schemes = [
    {
        scheme: 'HMAC-SHA256',
        useTimestamp: true,
        timestampValidationWindowInSeconds: 60,
        clients: [
            {
                clientId: 'clientOne',
                password: 'p455w0rd'
            }
        ]
    }
];

requestAuthorization.init(schemes);
```

## Installation

With [npm](http://npmjs.org) do

```bash
$ npm install request-authorization --save
```

## License

(MIT)

Copyright (c) 2015 Lee Crowe

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

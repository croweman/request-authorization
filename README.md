# request-authorization

[![build status](https://travis-ci.org/croweman/request-authorization.svg)](https://travis-ci.org/croweman/request-authorization)

Node module for signing and authorizing requests.

## Usage

Firstly the module will need to be initialized with schemes and there associated clients.

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

var isAuthorized = requestAuthorization.isAuthorized(authorizationHeader, data);

if (isAuthorized.result) {
    console.log('You are allowed in');
}
else {
    console.log('Denied');
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
});

function getData(req) {
    return req.params.id + JSON.stringify(req.body);
}
```

## Mention available schemes use timestamp, and the window


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

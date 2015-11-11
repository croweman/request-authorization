# request-authorization

[![build status](https://travis-ci.org/croweman/request-authorization.svg)](https://travis-ci.org/croweman/request-authorization)

Node module for signing and authorizing requests.

## Usage

Firstly the module will need to be initialized.

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

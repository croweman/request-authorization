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


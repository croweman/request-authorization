'use strict';

function parseAuthorizationHeader(authorizationHeader) {

    if(!authorizationHeader) return undefined;

    authorizationHeader = authorizationHeader.trim();

    var index = authorizationHeader.indexOf(' ');

    if(index == -1) return undefined;

    var authObject = {};
    authObject['scheme'] = authorizationHeader.substr(0, index);

    authorizationHeader = authorizationHeader.substr(index + 1)

    var args = authorizationHeader.split(';');

    args.forEach(function(val){

        val = val.trim();
        index = val.indexOf('=');

        if (index === -1) return;

        var key = val.substr(0, index);
        var value = val.substr(index + 1);

        if(!key.length || !value.length) return undefined;

        authObject[key] = value;
    });

    return authObject;

};

module.exports = {
    parseAuthorizationHeader: parseAuthorizationHeader
};
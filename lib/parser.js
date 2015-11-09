module.exports.parseAuthorizationHeader = function(authorizationHeader){

    if(!authorizationHeader) return undefined;

    authorizationHeader = authorizationHeader.trim();

    if(authorizationHeader.indexOf(' ') == -1) return undefined;

    var authObject = {};
    authObject['scheme'] = authorizationHeader.substr(0, authorizationHeader.indexOf(' '));

    authorizationHeader = authorizationHeader.substr(authorizationHeader.indexOf(' ') + 1)

    var arguments = authorizationHeader.split(';');

    arguments.forEach(function(val){

        val = val.trim();

        if(val.indexOf('=') === -1) return;

        var key = val.substr(0, val.indexOf('='));
        var value = val.substr(val.indexOf('=') + 1);

        if(!key.length || !value.length) return undefined;

        authObject[key] = value;
    });

    return authObject;

};
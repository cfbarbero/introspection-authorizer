var rp = require('request-promise'),
    config = require('./config.js'),
    authUtils = require('./authUtils.js');


// The entry point of this lambda function.
exports.handler = function(event, context) {
    console.log(event);

    // Get information about the function that is requested to be invoked.
    // Extract the HTTP method and the resource path from event.methodArn.
    var elements = authUtils.extractMethodAndPath(event.methodArn);
    var http_method = elements[0];
    var resource_path = elements[1];

    // [string] The access token that the client application presented.
    // The value comes from the request parameter 'authorizationToken'.
    var accessTokenToValidate = authUtils.extractAccessToken(event.authorizationToken);

    // If the request from the client does not contain an access token.
    if (!accessTokenToValidate) {
        // Write a log message and tell API Gateway to return "401 Unauthorized".
        console.log("[" + http_method + "] " + resource_path + " -> No access token.");
        context.fail("Unauthorized");
        return;
    }

    var tokenRequest = {
        url: config.authServerUrl + '/oauth/token',
        method: 'POST',
        auth: {
            user: config.clientId,
            pass: config.clientSecret
        },
        form: {
            grant_type: 'client_credentials',
        },
        json: true // Automatically parses the JSON string in the response
    };



    rp(tokenRequest)
        .then(function(tokenResponse) {
            console.log('Token Request', tokenRequest, tokenResponse);
            var accessToken = tokenResponse.accessToken;

            var introspectionRequest = {
                url: config.authServerUrl + '/oauth/token/introspect',
                method: 'POST',
                auth: {
                    bearer: accessToken,
                },
                body: {
                    token: accessTokenToValidate,
                },
                json: true // Automatically parses the JSON string in the response
            };

            rp(introspectionRequest)
                .then(function(introspectionResponse) {
                    console.log('Introspection Call', introspectionRequest, introspectionResponse);

                    if (introspectionResponse.active) {
                        // The access token is valid. Tell API Gateway that the access
                        // to the resource is allowed. The value of 'subject' property
                        // contained in a response from Authlete's introspection API is
                        // the subject (= unique identifier) of the user who is associated
                        // with the access token.
                        context.succeed(generate_policy(introspectionResponse.client_id, 'Allow', event.methodArn));
                    } else {
                        // Tell API Gateway that the access to the resource should be denined.
                        context.succeed(generate_policy(introspectionResponse.client_id, 'Deny', event.methodArn));
                    }
                })
                .catch(function(error) {
                    console.log('Introspection call failed', error);
                    context.fail('Internal Server Error');
                })

        })
        .catch(function(err) {
            console.log('Token call failed', err);
            context.fail('Internal Server Error');
        });
}

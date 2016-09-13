var rp = require('request-promise');

// Regular expression to extract an access token from
// Authorization header.
var BEARER_TOKEN_PATTERN = /^Bearer[ ]+([^ ]+)[ ]*$/i;

// A function to extract an access token from Authorization header.
//
// This function assumes the value complies with the format described
// in "RFC 6750, 2.1. Authorization Request Header Field". For example,
// if "Bearer 123" is given to this function, "123" is returned.
function extract_access_token(authorization) {
    // If the value of Authorization header is not available.
    if (!authorization) {
        // No access token.
        return null;
    }

    // Check if it matches the pattern "Bearer {access-token}".
    var result = BEARER_TOKEN_PATTERN.exec(authorization);

    // If the Authorization header does not match the pattern.
    if (!result) {
        // No access token.
        return null;
    }

    // Return the access token.
    return result[1];
}

// A function to extract the HTTP method and the resource path
// from event.methodArn.
function extract_method_and_path(arn) {
    // The value of 'arn' follows the format shown below.
    //
    //   arn:aws:execute-api:<regionid>:<accountid>:<apiid>/<stage>/<method>/<resourcepath>"
    //
    // See 'Enable Amazon API Gateway Custom Authorization' for details.
    //
    //   http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
    //

    // Check if the value of 'arn' is available just in case.
    if (!arn) {
        // HTTP method and a resource path are not available.
        return [null, null];
    }

    var arn_elements = arn.split(':', 6);
    var resource_elements = arn_elements[5].split('/', 4);
    var http_method = resource_elements[2];
    var resource_path = resource_elements[3];

    // Return the HTTP method and the resource path as a string array.
    return [http_method, resource_path];
}

function generate_policy(principal_id, effect, resource) {
    return {
        principalId: principal_id,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource
            }]
        }
    };
}


// The entry point of this lambda function.
exports.handler = function(event, context) {
    console.log(event);

    // Get information about the function that is requested to be invoked.
    // Extract the HTTP method and the resource path from event.methodArn.
    var elements = extract_method_and_path(event.methodArn);
    var http_method = elements[0];
    var resource_path = elements[1];

    // [string] The access token that the client application presented.
    // The value comes from the request parameter 'authorizationToken'.
    var access_token = extract_access_token(event.authorizationToken);

    // If the request from the client does not contain an access token.
    if (!access_token) {
        // Write a log message and tell API Gateway to return "401 Unauthorized".
        console.log("[" + http_method + "] " + resource_path + " -> No access token.");
        context.fail("Unauthorized");
        return;
    }

    var tokenRequest = {
        url: 'http://cbauthserver.us-east-1.elasticbeanstalk.com/oauth/token',
        method: 'POST',
        auth: {
            user: 'foo',
            pass: 'bar'
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
                url: 'http://cbauthserver.us-east-1.elasticbeanstalk.com/oauth/token/introspect',
                method: 'POST',
                auth: {
                    bearer: accessToken,
                },
                body: {
                    token: access_token,
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
        .catch(function(err){
          console.log('Token call failed', err);
          context.fail('Internal Server Error');
        });
}

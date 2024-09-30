# JWT Auth

WordPress JWT (JSON Web Token) Authentication allows you to do REST API authentication via token. It's a simple, non-complex, and easy to use.

This plugin probably is the most convenient way to do JWT Authentication in WordPress. Download it from [WordPress plugin page](https://wordpress.org/plugins/jwt-auth/).

- Support & question: [WordPress support forum](https://wordpress.org/support/plugin/jwt-auth/)
- Reporting plugin's bug: [GitHub issues tracker](https://github.com/usefulteam/jwt-auth/issues)
- [Discord channel](https://discord.gg/DgECpEg) also available.

## Requirements

### PHP

Minimum PHP version: 7.2

### Enable PHP HTTP Authorization Header

#### Shared Hosts

Most shared hosts have disabled the **HTTP Authorization Header** by default.

To enable this option you'll need to edit your **.htaccess** file by adding the following:

```
RewriteEngine on
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule ^(.*) - [E=HTTP_AUTHORIZATION:%1]
```

#### WPEngine

To enable this option you'll need to edit your **.htaccess** file by adding the following (see [this issue](https://github.com/Tmeister/wp-api-jwt-auth/issues/1)):

```
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
```

## Installation

### Through the WordPress Administrative Area:

- From WordPress administrative area, go to Plugins -> Add New
- Search for _JWT Auth_
- Install it
- Easily configure it (see [Configuration](#configuration) below)
- and then activate it

### Download Manually:

- Download the plugin from [WordPress plugins page](https://wordpress.org/plugins/jwt-auth/)
- Upload to your wp-content directory
- Easily configure it (see [Configuration](#configuration) below)
- Activate it from _Plugins_ menu in admin area

## Configuration

### Configurate the Secret Key

The JWT needs a **secret key** to sign the token. It must be unique and never be revealed.

To add the **secret key**, edit your wp-config.php file and add a new constant called **JWT_AUTH_SECRET_KEY**.

```php
define('JWT_AUTH_SECRET_KEY', 'your-top-secret-key');
```

You can use a string from here https://api.wordpress.org/secret-key/1.1/salt/

### Configurate CORs Support

This plugin has the option to enable [CORs](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) support.

To enable the CORs Support edit your wp-config.php file and add a new constant called **JWT_AUTH_CORS_ENABLE**

```php
define('JWT_AUTH_CORS_ENABLE', true);
```

Finally activate the plugin within the plugin dashboard.

## Namespace and Endpoints

When the plugin is activated, a new namespace is added.

```
/jwt-auth/v1
```

Also, three new endpoints are added to this namespace.

| Endpoint                              | HTTP Verb |
| ------------------------------------- | --------- |
| _/wp-json/jwt-auth/v1/token_          | POST      |
| _/wp-json/jwt-auth/v1/token/validate_ | POST      |
| _/wp-json/jwt-auth/v1/token/refresh_  | POST      |

## Requesting/ Generating Token

`/wp-json/jwt-auth/v1/token`

To generate token, submit a POST request to this endpoint. With `username` and `password` as the parameters.

It will validates the user credentials, and returns success response including a token if the authentication is correct or returns an error response if the authentication is failed.

You can use the optional parameter `device` with the device identifier to let user manage the device access in your profile. If this parameter is empty, it is ignored.

#### Sample of success response when trying to generate token:

```json
{
	"success": true,
	"statusCode": 200,
	"code": "jwt_auth_valid_credential",
	"message": "Credential is valid",
	"data": {
		"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcG9pbnRzLmNvdXZlZS5jby5pZCIsImlhdCI6MTU4ODQ5OTE0OSwibmJmIjoxNTg4NDk5MTQ5LCJleHAiOjE1ODkxMDM5NDksImRhdGEiOnsidXNlciI6eyJpZCI6MX19fQ.w3pf5PslhviHohmiGF-JlPZV00XWE9c2MfvBK7Su9Fw",
		"refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcG9pbnRzLmNvdXZlZS5jby5pZCIsImlhdCI6MTU4ODQ5OTE0OSwibmJmIjoxNTg4NDk5MTQ5LCJleHAiOjE1ODkxMDM5NDksImRhdGEiOnsidXNlciI6eyJpZCI6MX19fQ.w3pf5PslhviHohmiGF-JlPZV00XWE9c2MfvBK7Su9Fw",
		"id": 1,
		"email": "contactjavas@gmail.com",
		"nicename": "contactjavas",
		"firstName": "Bagus Javas",
		"lastName": "Heruyanto",
		"displayName": "contactjavas"
	}
}
```

#### Sample of error response when trying to generate token:

```json
{
	"success": false,
	"statusCode": 403,
	"code": "invalid_username",
	"message": "Unknown username. Try again or check your email address.",
	"data": []
}
```

Once you get the token, you must store it somewhere in your application. It can be:

- using **cookie**
- or using **localstorage**
- or using a wrapper like [localForage](https://localforage.github.io/localForage/) or [PouchDB](https://pouchdb.com/)
- or using local database like SQLite or [Hive](https://docs.hivedb.dev/#/)
- or your choice based on app you develop ;)

Then you should pass this token as _Bearer Authentication_ header to every API call. The header format is:

`Authorization: Bearer your-generated-token`

and here's an example:

```
"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcG9pbnRzLmNvdXZlZS5jby5pZCIsImlhdCI6MTU4ODQ5OTE0OSwibmJmIjoxNTg4NDk5MTQ5LCJleHAiOjE1ODkxMDM5NDksImRhdGEiOnsidXNlciI6eyJpZCI6MX19fQ.w3pf5PslhviHohmiGF-JlPZV00XWE9c2MfvBK7Su9Fw";
```

The **jwt-auth** will intercept every call to the server and will look for the authorization header, if the authorization header is present, it will try to decode the token and will set the user according with the data stored in it.

If the token is valid, the API call flow will continue as always.

## Validating Token

You likely **don't need** to validate the token your self. The plugin handle it for you like explained above.

But if you want to test or validate the token manually, then send a **POST** request to this endpoint (don't forget to set your _Bearer Authorization_ header):

`/wp-json/jwt-auth/v1/token/validate`

#### Valid Token Response

```
{
	"success": true,
	"statusCode": 200,
	"code": "jwt_auth_valid_token",
	"message": "Token is valid",
	"data": []
}
```

## Refreshing the Access Token

For security reasons, third-party applications that are integrating with your authentication server will not store the user's username and password. Instead they will store the refresh token in a user-specific storage that is only accessible for the user. The refresh token can be used to re-authenticate as the same user and generate a new access token.

When authenticating with `username` and `password` as the parameters to `/wp-json/jwt-auth/v1/token`, a refresh token is sent as a cookie in the response.

`/wp-json/jwt-auth/v1/token`

To generate new access token using the refresh token, submit a POST request to the token endpoint together with the `refresh_token` cookie.

Use the optional parameter `device` with the device identifier to associate the token with that device.

If the refresh token is valid, then you receive a new access token in the response.

By default, each access token expires after 10 minutes.


`/wp-json/jwt-auth/v1/token/refresh`

To generate new refresh token using the refresh token, submit a POST request to the token refresh endpoint together with the `refresh_token` cookie.

Use the optional parameter `device` with the device identifier to associate the refresh token with that device.

If the refresh token is valid, then you receive a new refresh token as a cookie in the response.

By default, each refresh token expires after 30 days.


### Refresh Token Rotation

Whenever you are authenticating afresh or refreshing the refresh token, only the last issued refresh token remains valid. All previously issued refresh tokens can no longer be used.

This means that a refresh token cannot be shared. To allow multiple devices to authenticate in parallel without losing access after another device re-authenticated, use the parameter `device` with the device identifier to associate the refresh token only with that device.

```sh
curl -F device="abc-def" -F username=myuser -F password=mypass /wp-json/jwt-auth/v1/token
```
```sh
# For a cookie flow
curl -F device="abc-def" -b "refresh_token=eyJ0eXAiOi..." /wp-json/jwt-auth/v1/token

# For a body flow
curl -F device="abc-def" -d "refresh_token=eyJ0eXAiOi..." /wp-json/jwt-auth/v1/token

# For a parameter flow
curl -F device="abc-def" "/wp-json/jwt-auth/v1/token?refresh_token=eyJ0eXAiOi..."
```
```sh
# For a cookie flow
curl -F device="abc-def" -b "refresh_token=eyJ0eXAiOi..." /wp-json/jwt-auth/v1/token/refresh

# For a body flow
curl -F device="abc-def" -d "refresh_token=eyJ0eXAiOi..." /wp-json/jwt-auth/v1/token/refresh

# For a parameter flow
curl -F device="abc-def" "/wp-json/jwt-auth/v1/token/refresh?refresh_token=eyJ0eXAiOi..."
```


## Error Responses

If the token is invalid an error will be returned. Here are some samples of errors:

**No Secret Key**

```json
{
	"success": false,
	"statusCode": 500,
	"code": "jwt_auth_bad_config",
	"message": "JWT is not configured properly.",
	"data": []
}
```

**No HTTP_AUTHORIZATION Header**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_no_auth_header",
	"message": "Authorization header not found.",
	"data": []
}
```

**Bad Iss**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_bad_iss",
	"message": "The iss do not match with this server.",
	"data": []
}
```

**Invalid Signature**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_invalid_token",
	"message": "Signature verification failed",
	"data": []
}
```

**Incomplete Payload**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_bad_request",
	"message": "User ID not found in the token.",
	"data": []
}
```

**User Not Found**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_user_not_found",
	"message": "User doesn't exist",
	"data": []
}
```

**Expired Token**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_invalid_token",
	"message": "Expired token",
	"data": []
}
```

**Obsolete Token**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_obsolete_token",
	"message": "Token is obsolete",
	"data": []
}
```

**Invalid Refresh Token**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_invalid_refresh_token",
	"message": "Device not found in the refresh token.",
	"data": []
}
```

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_invalid_refresh_token",
	"message": "Invalid token type",
	"data": []
}
```

**Obsolete Refresh Token**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_obsolete_refresh_token",
	"message": "Refresh token is obsolete",
	"data": []
}
```

**Expired Refresh Token**

```json
{
	"success": false,
	"statusCode": 401,
	"code": "jwt_auth_expired_refresh_token",
	"message": "Refresh token has expired",
	"data": []
}
```

## Available Filter Hooks

**JWT Auth** is developer friendly and has some filters available to override the default settings.

### jwt_auth_cors_allow_headers

The `jwt_auth_cors_allow_headers` allows you to modify the available headers when the CORs support is enabled.

Default Value:

```
'X-Requested-With, Content-Type, Accept, Origin, Authorization'
```

Usage example:

```php
/**
 * Change the allowed CORS headers.
 *
 * @param string $headers The allowed headers.
 * @return string The allowed headers.
 */
add_filter(
	'jwt_auth_cors_allow_headers',
	function ( $headers ) {
		// Modify the headers here.
		return $headers;
	}
);
```


### jwt_auth_flow

The **jwt_auth_flow** allows you to decide which flow use for current request.

The supported options are:
- cookie __*(default)*__
- body
- query
- header

To enable the desired refresh token flow add an hook to your theme's functions.php file.
```php
/**
 * Change the flow for refresh token.
 *
 * @param string $flow The current flow.
 */
add_filter(
	'jwt_auth_flow',
	function ( $headers ) {
	if (wp_doing_ajax()) {
		// Modify the flow here.
        return 'body';
	}
	return $flow;
);
```

This value will be used to establish from with part of the request the refresh token will be taken.

### jwt_auth_authorization_header

The **jwt_auth_authorization_header** allows you to modify the Authorization header key used to validating a token. Useful when the server already uses the 'Authorization' key for another auth method.

Default value:

```
'HTTP_AUTHORIZATION'
```

Usage example:

```php
/**
 * Modify the response of Authorization header key.
 *
 * @param string $header The Authorization header key.
 * .
 * @return string The Authorization header key.
 */
add_filter(
	'jwt_auth_authorization_header',
	function ( $header ) {
		// Modify the response here.
		return $header;
	},
	10,
	1
);
```


### jwt_auth_iss

The **jwt_auth_iss** allows you to change the [**iss**](https://tools.ietf.org/html/rfc7519#section-4.1.1) value before the payload is encoded to be a token.

Default Value:

```
get_bloginfo( 'url' )
```

Usage example:

```php
/**
 * Change the token issuer.
 *
 * @param string $iss The token issuer.
 * @return string The token issuer.
 */
add_filter(
	'jwt_auth_iss',
	function ( $iss ) {
		// Modify the "iss" here.
		return $iss;
	}
);
```

### jwt_auth_not_before

#### alias for [jwt_auth_toke_not_before](#jwt_auth_token_not_before)

The `jwt_auth_not_before` allows you to change the [**nbf**](https://tools.ietf.org/html/rfc7519#section-4.1.5) value before the payload is encoded to be a token

Default Value:

```
// Creation time.
time()
```

Usage example:

```php
/**
 * Change the token's nbf value.
 *
 * @param int $not_before The default "nbf" value in timestamp.
 * @param int $issued_at The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
	'jwt_auth_not_before',
	function ( $not_before, $issued_at ) {
		// Modify the "not_before" here.
		return $not_before;
	},
	10,
	2
);
```

### jwt_auth_token_not_before

The `jwt_auth_token_not_before` allows you to change the [**nbf**](https://tools.ietf.org/html/rfc7519#section-4.1.5) value before the payload is encoded to be a token

Default Value:

```
// Creation time.
time()
```

Usage example:

```php
/**
 * Change the token's nbf value.
 *
 * @param int $not_before The default "nbf" value in timestamp.
 * @param int $issued_at The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
	'jwt_auth_token_not_before',
	function ( $not_before, $issued_at ) {
		// Modify the "not_before" here.
		return $not_before;
	},
	10,
	2
);
```

### jwt_auth_expire

#### alias for [jwt_auth_token_expire](#jwt_auth_token_expire)

The `jwt_auth_expire` allows you to change the [**exp**](https://tools.ietf.org/html/rfc7519#section-4.1.4) value before the payload is encoded to be a token

Default Value:

```
time() + (MINUTE_IN_SECONDS * 10)
```

Usage example:

```php
/**
 * Change the token's expire value.
 *
 * @param int $expire The default "exp" value in timestamp.
 * @param int $issued_at The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
	'jwt_auth_expire',
	function ( $expire, $issued_at ) {
		// Modify the "expire" here.
		return $expire;
	},
	10,
	2
);
```


### jwt_auth_token_expire

The `jwt_auth_token_expire` allows you to change the [**exp**](https://tools.ietf.org/html/rfc7519#section-4.1.4) value before the payload is encoded to be a token

Default Value:

```
time() + (MINUTE_IN_SECONDS * 10)
```

Usage example:

```php
/**
 * Change the token's expire value.
 *
 * @param int $expire The default "exp" value in timestamp.
 * @param int $issued_at The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
	'jwt_auth_token_expire',
	function ( $expire, $issued_at ) {
		// Modify the "expire" here.
		return $expire;
	},
	10,
	2
);
```



### jwt_auth_refresh_not_before

The `jwt_auth_refresh_not_before` allows you to change the [**nbf**](https://tools.ietf.org/html/rfc7519#section-4.1.5) value before the payload is encoded to be a refresh token

Default Value:

```
// Creation time.
time()
```

Usage example:

```php
/**
 * Change the refresh token's nbf value.
 *
 * @param int $not_before The default "nbf" value in timestamp.
 * @param int $issued_at The "iat" value in timestamp.
 *
 * @return int The "nbf" value.
 */
add_filter(
	'jwt_auth_refresh_not_before',
	function ( $not_before, $issued_at ) {
		// Modify the "not_before" here.
		return $not_before;
	},
	10,
	2
);
```

### jwt_auth_refresh_expire

The `jwt_auth_refresh_expire` filter hook allows you to change the [**exp**](https://tools.ietf.org/html/rfc7519#section-4.1.4) value before the payload is encoded to be a refresh token

Default Value:

```
time() + (DAY_IN_SECONDS * 30)
```

Usage example:

```php
/**
 * Change the refresh token's expiration time.
 *
 * @param int $expire The default expiration timestamp.
 * @param int $issued_at The current time.
 *
 * @return int The custom refresh token expiration timestamp.
 */
add_filter(
	'jwt_auth_refresh_expire',
	function ( $expire, $issued_at ) {
		// Modify the "expire" here.
		return $expire;
	},
	10,
	2
);
```

### jwt_auth_alg

The `jwt_auth_alg` allows you to change the supported signing [algorithm](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40) for your application.

Default Value:

```
'HS256'
```

Usage example:

```php
/**
 * Change the token's signing algorithm.
 *
 * @param string $alg The default supported signing algorithm.
 * @return string The supported signing algorithm.
 */
add_filter(
	'jwt_auth_alg',
	function ( $alg ) {
		// Change the signing algorithm here.
		return $alg;
	}
);
```

### jwt_auth_payload

The `jwt_auth_payload` allows you to modify all the payload / token data before being encoded and signed.

Default value:

```php
<?php
$token = array(
    'iss' => get_bloginfo('url'),
    'iat' => $issued_at,
    'nbf' => $not_before,
    'exp' => $expire,
    'data' => array(
        'user' => array(
            'id' => $user->ID,
        )
    )
);
```

Usage example:

```php
/**
 * Modify the payload/ token's data before being encoded & signed.
 *
 * @param array $payload The default payload
 * @param WP_User $user The authenticated user.
 * .
 * @return array The payload/ token's data.
 */
add_filter(
	'jwt_auth_payload',
	function ( $payload, $user ) {
		// Modify the payload here.
		return $payload;
	},
	10,
	2
);
```

### jwt_auth_valid_credential_response

The `jwt_auth_valid_credential_response` allows you to modify the valid credential response when generating a token.

Default value:

```php
<?php
$response = array(
    'success'    => true,
    'statusCode' => 200,
    'code'       => 'jwt_auth_valid_credential',
    'message'    => __( 'Credential is valid', 'jwt-auth' ),
    'data'       => array(
        'token'       => $token,
        'id'          => $user->ID,
        'email'       => $user->user_email,
        'nicename'    => $user->user_nicename,
        'firstName'   => $user->first_name,
        'lastName'    => $user->last_name,
        'displayName' => $user->display_name,
    ),
);
```

Usage example:

```php
/**
 * Modify the response of valid credential.
 *
 * @param array $response The default valid credential response.
 * @param WP_User $user The authenticated user.
 * .
 * @return array The valid credential response.
 */
add_filter(
	'jwt_auth_valid_credential_response',
	function ( $response, $user ) {
		// Modify the response here.
		return $response;
	},
	10,
	2
);
```

### jwt_auth_valid_token_response

The **jwt_auth_valid_token_response** allows you to modify the valid token response when validating a token.

Default value:

```php
<?php
$response = array(
	'success'    => true,
	'statusCode' => 200,
	'code'       => 'jwt_auth_valid_token',
	'message'    => __( 'Token is valid', 'jwt-auth' ),
	'data'       => array(),
);
```

Usage example:

```php
/**
 * Modify the response of valid token.
 *
 * @param array $response The default valid token response.
 * @param WP_User $user The authenticated user.
 * @param string $token The raw token.
 * @param array $payload The token data.
 * .
 * @return array The valid token response.
 */
add_filter(
	'jwt_auth_valid_token_response',
	function ( $response, $user, $token, $payload ) {
		// Modify the response here.
		return $response;
	},
	10,
	4
);
```


### jwt_auth_extra_token_check

The **jwt_auth_extra_token_check** allows you to add extra criterias to validate the token. If empty, has no problem to proceed. Use empty value to bypass the filter. Any other value will block the token access and returns response with code `jwt_auth_obsolete_token`.

Default value:

```
''
```

Usage example:

```php
/**
 * Modify the validation of token. No-empty values block token validation.
 *
 * @param array $response An empty value ''.
 * @param WP_User $user The authenticated user.
 * @param string $token The raw token.
 * @param array $payload The token data.
 * .
 * @return array The valid token response.
 */
add_filter(
	'jwt_auth_extra_token_check',
	function ( $response, $user, $token, $payload ) {
		// Modify the response here.
		return $response;
	},
	10,
	4
);
```


## Automated Tests

There are end-to-end tests you can run to confirm that the API works correctly:

```console
$ URL=https://example.local USERNAME=myuser PASSWORD=mypass FLOW=cookie composer run test
> ./vendor/bin/phpunit
PHPUnit 9.5.25 #StandWithUkraine

...............                                                   15 / 15 (100%)

Time: 00:48.086, Memory: 8.00 MB

OK (15 tests, 143 assertions)
```


## Credits

- [PHP-JWT from firebase](https://github.com/firebase/php-jwt)
- [JWT Authentication for WP REST API](https://wordpress.org/plugins/jwt-authentication-for-wp-rest-api/). This _JWT-Auth_ plugin was a "copy-then-modify" of _JWT Authentication for WP REST API_ plugin.
- [Devices utility by pesseba](https://github.com/pesseba)
- The [awesome maintainers](https://github.com/usefulteam/jwt-auth/collaborators) and [contributors](https://github.com/usefulteam/jwt-auth/graphs/contributors)

## License

[GPL-3.0 License](https://oss.ninja/gpl-3.0?organization=Useful%20Team&project=WordPress%20JWT%20Auth)

## Keep This Plugin Alive & Maintained

You can help us to keep this plugin alive and continue to maintain it by:

- Giving **5 Stars** [review here](https://wordpress.org/plugins/jwt-auth/)
- Answering [GitHub issues](https://github.com/usefulteam/jwt-auth/issues) or questions on Discord.
- Testing / participating to the submitted [PRs](https://github.com/usefulteam/jwt-auth/pulls)

Thank You!

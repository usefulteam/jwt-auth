=== JWT Auth - WordPress JSON Web Token Authentication ===

Contributors: contactjavas
Donate link: https://www.paypal.me/bagusjavas
Tags: jwt, jwt auth, jwt authentication, jwt token, json web token, wp-json, json web token authentication, wp-api
Requires at least: 5.2
Tested up to: 5.4
Requires PHP: 7.2
Stable tag: trunk
License: GPL-3.0 License
License URI: https://oss.ninja/gpl-3.0?organization=Useful%20Team&project=WordPress%20JWT%20Auth

== Description ==
WordPress JSON Web Token Authentication allows you to do REST API authentication via token. It is a simple, non-complex, and easy to use.

This plugin probably is the most convenient way to do JWT Authentication in WordPress.

## Enable PHP HTTP Authorization Header

= Shared Hosts =

Most shared hosts have disabled the **HTTP Authorization Header** by default.

To enable this option you'll need to edit your **.htaccess** file by adding the following:

`
RewriteEngine on
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule ^(.*) - [E=HTTP_AUTHORIZATION:%1]
`

= WPEngine =

To enable this option you'll need to edit your **.htaccess** file by adding the following (see [this issue](https://github.com/Tmeister/wp-api-jwt-auth/issues/1)):

`
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
`

## Configuration

= Configurate the Secret Key =

The JWT needs a **secret key** to sign the token. This **secret key** must be unique and never revealed.

To add the **secret key**, edit your wp-config.php file and add a new constant called **JWT_AUTH_SECRET_KEY**.

`
define('JWT_AUTH_SECRET_KEY', 'your-top-secret-key');
`

You can use a string from [here](https://api.wordpress.org/secret-key/1.1/salt/)

= Configurate CORs Support =

This plugin has the option to activate [CORs](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) support.

To enable the CORs Support edit your wp-config.php file and add a new constant called **JWT_AUTH_CORS_ENABLE**

`
define('JWT_AUTH_CORS_ENABLE', true);
`

## Namespace and Endpoints

When the plugin is activated, a new namespace is added.

`
/jwt-auth/v1
`

Also, two new endpoints are added to this namespace.

**POST**

`
/wp-json/jwt-auth/v1/token
`

**POST**

`
/wp-json/jwt-auth/v1/token/validate
`

## Requesting/ Generating Token

`
/wp-json/jwt-auth/v1/token
`

To generate token, submit a POST request to this entry point. With `username` and `password` as the parameters.

It will validates the user credentials, and returns success response including a token if the authentication is correct or returns an error response if the authentication is failed.

= Sample of success response when trying to generate token: =

`
{
	"success": true,
	"statusCode": 200,
	"code": "jwt_auth_valid_credential",
	"message": "Credential is valid",
	"data": {
		"token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcG9pbnRzLmNvdXZlZS5jby5pZCIsImlhdCI6MTU4ODQ5OTE0OSwibmJmIjoxNTg4NDk5MTQ5LCJleHAiOjE1ODkxMDM5NDksImRhdGEiOnsidXNlciI6eyJpZCI6MX19fQ.w3pf5PslhviHohmiGF-JlPZV00XWE9c2MfvBK7Su9Fw",
		"id": 1,
		"email": "contactjavas@gmail.com",
		"nicename": "contactjavas",
		"firstName": "Bagus Javas",
		"lastName": "Heruyanto",
		"displayName": "contactjavas"
	}
}
`

= Sample of error response when trying to generate token: =

`
{
	"success": false,
	"statusCode": 403,
	"code": "invalid_username",
	"message": "Unknown username. Check again or try your email address.",
	"data": []
}
`

Once you get the token, you must store it somewhere in your application, e.g. in a **cookie** or using **localstorage**.
Then you should pass this token to every API call.

The **jwt-auth** will intercept every call to the server and will look for the authorization header, if the authorization header is present, it will try to decode the token and will set the user according with the data stored in it.

If the token is valid, the API call flow will continue as always.

## Validating Token

`
/wp-json/jwt-auth/v1/token/validate
`

This simple endpoint is to validate a token; you will only need to make a POST request sending the *Authorization header*.

= Valid Token Response: =

`
{
	"success": true,
	"statusCode": 200,
	"code": "jwt_auth_valid_token",
	"message": "Token is valid",
	"data": []
}
`

## Errors

If the token is invalid an error will be returned. Here are some samples of errors:

= No Secret Key =

`
{
	"success": false,
	"statusCode": 403,
	"code": "jwt_auth_bad_config",
	"message": "JWT is not configurated properly.",
	"data": []
}
`

= No HTTP_AUTHORIZATION Header =

`
{
	"success": false,
	"statusCode": 403,
	"code": "jwt_auth_no_auth_header",
	"message": "Authorization header not found.",
	"data": []
}
`

= Bad Iss =

`
{
	"success": false,
	"statusCode": 403,
	"code": "jwt_auth_bad_iss",
	"message": "The iss do not match with this server.",
	"data": []
}
`

= Invalid Signature =

`
{
	"success": false,
	"statusCode": 403,
	"code": "jwt_auth_invalid_token",
	"message": "Signature verification failed",
	"data": []
}
`

= Expired Token =

`
{
	"success": false,
	"statusCode": 403,
	"code": "jwt_auth_invalid_token",
	"message": "Expired token",
	"data": []
}
`

## Available Hooks

JWT Auth is developer friendly and has some filters available to override the default settings.

= jwt_auth_cors_allow_headers =

The `jwt_auth_cors_allow_headers` allows you to modify the available headers when the CORs support is enabled.

Default Value:

`
'Access-Control-Allow-Headers, Content-Type, Authorization'
`

= jwt_auth_not_before =

The `jwt_auth_not_before` allows you to change the [**nbf**](https://tools.ietf.org/html/rfc7519#section-4.1.5) value before the token is created.

Default Value:

`
// Creation time.
time()
`

= jwt_auth_expire =

The `jwt_auth_expire` allows you to change the value [**exp**](https://tools.ietf.org/html/rfc7519#section-4.1.4) before the token is created.

Default Value:

`
time() + (DAY_IN_SECONDS * 7)
`

= jwt_auth_token_payload =

The `jwt_auth_token_payload` allows you to modify all the token data before being encoded and signed.

Default value:

`
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
`

= jwt_auth_token_response =

The `jwt_auth_token_response` allows you to modify the valid response before being dispatched to the client.

Default value:

`
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
`

## Credits
[PHP-JWT from firebase](https://github.com/firebase/php-jwt)
[JWT Authentication for WP REST API](https://wordpress.org/plugins/jwt-authentication-for-wp-rest-api/)

== Installation ==

**Enable PHP HTTP Authorization Header**

= Shared Hosts =

Most shared hosts have disabled the **HTTP Authorization Header** by default.

To enable this option you'll need to edit your **.htaccess** file by adding the following:

`
RewriteEngine on
RewriteCond %{HTTP:Authorization} ^(.*)
RewriteRule ^(.*) - [E=HTTP_AUTHORIZATION:%1]
`

= WPEngine =

To enable this option you'll need to edit your **.htaccess** file by adding the following (see [this issue](https://github.com/Tmeister/wp-api-jwt-auth/issues/1)):

`
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
`

= Installing Through the WordPress Administrative Area: =
- From WordPress administrative area, go to Plugins -> Add New
- Search for _JWT Auth_
- Install it
- Easily configure it (see "Configuration" below)
- and then activate it

= Installing by Downloading Manually: =
- Download the plugin from [WordPress plugins page](https://wordpress.org/plugins/jwt-auth/)
- Upload to your wp-content directory
- Easily configure it (see "Configuration" below)
- Activate it from _Plugins_ menu in admin area

**Configuration**

= Configurate the Secret Key =

The JWT needs a **secret key** to sign the token. It must be unique and never be revealed.

To add the **secret key**, edit your wp-config.php file and add a new constant called **JWT_AUTH_SECRET_KEY**.

`
define('JWT_AUTH_SECRET_KEY', 'your-top-secret-key');
`

You can use a string from [here](https://api.wordpress.org/secret-key/1.1/salt/)

= Configurate CORs Support =

This plugin has the option to enable [CORs](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) support.

To enable the CORs Support edit your wp-config.php file and add a new constant called **JWT_AUTH_CORS_ENABLE**

`
define('JWT_AUTH_CORS_ENABLE', true);
`

Finally activate the plugin within the plugin dashboard.

== Frequently Asked Questions ==
= Do you have GitHub repository for this plugin? =

You can visit the GitHub repository at https://github.com/usefulteam/jwt-auth/

= I use this plugin on my projects. I want this plugin to keep alive and maintained, how can i help? =

You can help this plugin stay alive and maintained by giving **5 Stars** Rating/ Review or:
- https://paypal.me/bagusjavas
- https://www.patreon.com/bagus

== Screenshots ==
1. Success response when trying to generate token
2. Error response when trying to generate token
3. Other error responses

== Changelog ==
= 0.1.0 =
- Initial release

== Upgrade Notice ==
Just update the plugin
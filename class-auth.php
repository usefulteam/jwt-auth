<?php
/**
 * Setup JWT-Auth.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

use Exception;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * The public-facing functionality of the plugin.
 */
class Auth {
	/**
	 * The namespace to add to the api calls.
	 *
	 * @var string The namespace to add to the api call
	 */
	private $namespace;

	/**
	 * Store errors to display if the JWT is wrong
	 *
	 * @var WP_REST_Response
	 */
	private $jwt_error = null;

	/**
	 * Collection of translate-able messages.
	 *
	 * @var array
	 */
	private $messages = array();

	/**
	 * The REST API slug.
	 *
	 * @var string
	 */
	private $rest_api_slug = 'wp-json';

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
		$this->namespace = 'jwt-auth/v1';

		$this->messages = array(
			'jwt_auth_no_auth_header'  => __( 'Authorization header not found.', 'jwt-auth' ),
			'jwt_auth_bad_auth_header' => __( 'Authorization header malformed.', 'jwt-auth' ),
		);
	}

	/**
	 * Add the endpoints to the API
	 */
	public function register_rest_routes() {
		register_rest_route(
			$this->namespace,
			'token',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'get_token' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			$this->namespace,
			'token/validate',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'validate_token' ),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			$this->namespace,
			'token/refresh',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'refresh_token' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Add CORs suppot to the request.
	 */
	public function add_cors_support() {
		global $wp_version;

		$enable_cors = defined( 'JWT_AUTH_CORS_ENABLE' ) ? JWT_AUTH_CORS_ENABLE : false;

		if ( ! $enable_cors ) {
			return;
		}

		// Hook exists since 5.5.0
		if ( version_compare( $wp_version, '5.5.0', '>=' ) ) {
			add_filter( 'rest_allowed_cors_headers', function ( array $headers ) {

				$filters = apply_filters( 'jwt_auth_cors_allow_headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization, Cookie' );

				$split = preg_split( "/[\s,]+/", $filters );

				return array_unique( array_merge( $headers, $split ) );
			} );
		} else if ( ! headers_sent() ) {
			$headers = apply_filters( 'jwt_auth_cors_allow_headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization, Cookie' );

			header( sprintf( 'Access-Control-Allow-Headers: %s', $headers ) );
		}
	}

	/**
	 * Authenticate user either via wp_authenticate or custom auth (e.g: OTP).
	 *
	 * @param string $username The username.
	 * @param string $password The password.
	 * @param mixed  $custom_auth The custom auth data (if any).
	 *
	 * @return WP_User|WP_Error $user Returns WP_User object if success, or WP_Error if failed.
	 */
	public function authenticate_user( $username, $password, $custom_auth = '' ) {
		// If using custom authentication.
		if ( $custom_auth ) {
			$custom_auth_error = new WP_Error( 'jwt_auth_custom_auth_failed', __( 'Custom authentication failed.', 'jwt-auth' ) );

			/**
			 * Do your own custom authentication and return the result through this filter.
			 * It should return either WP_User or WP_Error.
			 */
			$user = apply_filters( 'jwt_auth_do_custom_auth', $custom_auth_error, $username, $password, $custom_auth );
		} else {
			$user = wp_authenticate( $username, $password );
		}

		return $user;
	}

	/**
	 * Get token by sending POST request to jwt-auth/v1/token.
	 *
	 * @param WP_REST_Request $request The request.
	 * @return WP_REST_Response The response.
	 */
	public function get_token( WP_REST_Request $request ) {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;

		$username    = $request->get_param( 'username' );
		$password    = $request->get_param( 'password' );
		$custom_auth = $request->get_param( 'custom_auth' );

		// First thing, check the secret key if not exist return a error.
		if ( ! $secret_key ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 500,
					'code'       => 'jwt_auth_bad_config',
					'message'    => __( 'JWT is not configured properly.', 'jwt-auth' ),
					'data'       => array(),
				),
				500
			);
		}

		if ( isset( $_COOKIE['refresh_token'] ) ) {
			$device  = $request->get_param( 'device' ) ?: '';
			$user_id = $this->validate_refresh_token( $_COOKIE['refresh_token'], $device );

			// If we receive a REST response, then validation failed.
			if ( $user_id instanceof WP_REST_Response ) {
				return $user_id;
			}
			$user = get_user_by( 'id', $user_id );
		} else {
			$user = $this->authenticate_user( $username, $password, $custom_auth );
		}

		// If the authentication is failed return error response.
		if ( is_wp_error( $user ) ) {
			$error_code = $user->get_error_code();

			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => $error_code,
					'message'    => wp_strip_all_tags( $user->get_error_message( $error_code ) ),
					'data'       => array(),
				),
				401
			);
		}

		// Valid credentials, the user exists, let's generate the token.
		$response = $this->generate_token( $user, false );

		// Add the refresh token as a HttpOnly cookie to the response.
		if ( $username && $password ) {
			$this->send_refresh_token( $user, $request );
		}

		return $response;
	}

	/**
	 * Generate access token.
	 *
	 * @param WP_User $user The WP_User object.
	 * @param bool    $return_raw Whether or not to return as raw token string.
	 *
	 * @return WP_REST_Response|string Return as raw token string or as a formatted WP_REST_Response.
	 */
	public function generate_token( $user, $return_raw = true ) {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		$issued_at  = time();
		$not_before = $issued_at;
		$not_before = apply_filters( 'jwt_auth_not_before', $not_before, $issued_at );
		$expire     = $issued_at + ( MINUTE_IN_SECONDS * 10 );
		$expire     = apply_filters( 'jwt_auth_expire', $expire, $issued_at );

		$payload = array(
			'iss'  => $this->get_iss(),
			'iat'  => $issued_at,
			'nbf'  => $not_before,
			'exp'  => $expire,
			'data' => array(
				'user' => array(
					'id' => $user->ID,
				),
			),
		);

		$alg = $this->get_alg();

		// Let the user modify the token data before the sign.
		$token = JWT::encode( apply_filters( 'jwt_auth_payload', $payload, $user ), $secret_key, $alg );

		// If return as raw token string.
		if ( $return_raw ) {
			return $token;
		}

		// The token is signed, now create object with basic info of the user.
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

		// Let the user modify the data before send it back.
		return apply_filters( 'jwt_auth_valid_credential_response', $response, $user );
	}

	/**
	 * Sends a new refresh token.
	 *
	 * @param \WP_User $user The WP_User object.
	 * @param \WP_REST_Request $request The request.
	 *
	 * @return void
	 */
	public function send_refresh_token( \WP_User $user, \WP_REST_Request $request ) {
		$refresh_token = bin2hex( random_bytes( 32 ) );
		$created       = time();
		$expires       = $created + DAY_IN_SECONDS * 30;
		$expires       = apply_filters( 'jwt_auth_refresh_expire', $expires, $created );

		setcookie( 'refresh_token', $user->ID . '.' . $refresh_token, $expires, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

		// Save new refresh token for the user, replacing the previous one.
		// The refresh token is rotated for the passed device only, not affecting
		// other devices.
		$user_refresh_tokens = get_user_meta( $user->ID, 'jwt_auth_refresh_tokens', true );
		if ( ! is_array( $user_refresh_tokens ) ) {
			$user_refresh_tokens = array();
		}
		$device = $request->get_param( 'device' ) ?: '';
		$user_refresh_tokens[ $device ] = array(
			'token'   => $refresh_token,
			'expires' => $expires,
		);
		update_user_meta( $user->ID, 'jwt_auth_refresh_tokens', $user_refresh_tokens );

		// Store next expiry for cron_purge_expired_refresh_tokens event.
		$expires_next = $expires;
		foreach ( $user_refresh_tokens as $device ) {
			if ( $device['expires'] < $expires_next ) {
				$expires_next = $device['expires'];
			}
		}
		update_user_meta( $user->ID, 'jwt_auth_refresh_tokens_expires_next', $expires_next );
	}

	/**
	 * Get the token issuer.
	 *
	 * @return string The token issuer (iss).
	 */
	public function get_iss() {
		return apply_filters( 'jwt_auth_iss', get_bloginfo( 'url' ) );
	}

	/**
	 * Get the supported jwt auth signing algorithm.
	 *
	 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
	 *
	 * @return string $alg
	 */
	public function get_alg() {
		return apply_filters( 'jwt_auth_alg', 'HS256' );
	}

	/**
	 * Determine if given response is an error response.
	 *
	 * @param mixed $response The response.
	 * @return boolean
	 */
	public function is_error_response( $response ) {
		if ( ! empty( $response ) && property_exists( $response, 'data' ) && is_array( $response->data ) ) {
			if ( ! isset( $response->data['success'] ) || ! $response->data['success'] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Public token validation function based on Authorization header.
	 *
	 * @param bool $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return WP_REST_Response | Array Returns WP_REST_Response or token's $payload.
	 */
	public function validate_token( $return_response = true ) {
		/**
		 * Looking for the HTTP_AUTHORIZATION header, if not present just
		 * return the user.
		 */
		$headerkey = apply_filters( 'jwt_auth_authorization_header', 'HTTP_AUTHORIZATION' );
		$auth      = isset( $_SERVER[ $headerkey ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $headerkey ] ) ) : false;

		// Double check for different auth header string (server dependent).
		if ( ! $auth ) {
			$auth = isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) : false;
		}

		if ( ! $auth ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_no_auth_header',
					'message'    => $this->messages['jwt_auth_no_auth_header'],
					'data'       => array(),
				),
				401
			);
		}

		/**
		 * The HTTP_AUTHORIZATION is present, verify the format.
		 * If the format is wrong return the user.
		 */
		list($token) = sscanf( $auth, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_bad_auth_header',
					'message'    => $this->messages['jwt_auth_bad_auth_header'],
					'data'       => array(),
				),
				401
			);
		}

		// Get the Secret Key.
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;

		if ( ! $secret_key ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_bad_config',
					'message'    => __( 'JWT is not configured properly.', 'jwt-auth' ),
					'data'       => array(),
				),
				401
			);
		}

		// Try to decode the token.
		try {
			$alg     = $this->get_alg();
			$payload = JWT::decode( $token, new Key( $secret_key , $alg ));

			// The Token is decoded now validate the iss.
			if ( $payload->iss !== $this->get_iss() ) {
				// The iss do not match, return error.
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_bad_iss',
						'message'    => __( 'The iss do not match with this server.', 'jwt-auth' ),
						'data'       => array(),
					),
					401
				);
			}

			// Check the user id existence in the token.
			if ( ! isset( $payload->data->user->id ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_bad_request',
						'message'    => __( 'User ID not found in the token.', 'jwt-auth' ),
						'data'       => array(),
					),
					401
				);
			}

			// So far so good, check if the given user id exists in db.
			$user = get_user_by( 'id', $payload->data->user->id );

			if ( ! $user ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_user_not_found',
						'message'    => __( "User doesn't exist", 'jwt-auth' ),
						'data'       => array(),
					),
					401
				);
			}

			// Check extra condition if exists.
			$failed_msg = apply_filters( 'jwt_auth_extra_token_check', '', $user, $token, $payload );

			if ( ! empty( $failed_msg ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_obsolete_token',
						'message'    => __( 'Token is obsolete', 'jwt-auth' ),
						'data'       => array(),
					),
					401
				);
			}

			// Everything looks good, return the payload if $return_response is set to false.
			if ( ! $return_response ) {
				return $payload;
			}

			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'code'       => 'jwt_auth_valid_token',
				'message'    => __( 'Token is valid', 'jwt-auth' ),
				'data'       => array(),
			);

			$response = apply_filters( 'jwt_auth_valid_token_response', $response, $user, $token, $payload );

			// Otherwise, return success response.
			return new WP_REST_Response( $response );
		} catch ( Exception $e ) {
			// Something is wrong when trying to decode the token, return error response.
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_invalid_token',
					'message'    => $e->getMessage(),
					'data'       => array(),
				),
				401
			);
		}
	}

	/**
	 * Validates refresh token and generates a new refresh token.
	 *
	 * @param WP_REST_Request $request The request.
	 * @return WP_REST_Response Returns WP_REST_Response.
	 */
	public function refresh_token( WP_REST_Request $request ) {
		if ( ! isset( $_COOKIE['refresh_token'] ) ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_no_auth_cookie',
					'message'    => __( 'Refresh token cookie not found.', 'jwt-auth' ),
				),
				401
			);
		}
		$device = $request->get_param( 'device' ) ?: '';

		$user_id = $this->validate_refresh_token( $_COOKIE['refresh_token'], $device );
		if ( $user_id instanceof WP_REST_Response ) {
			return $user_id;
		}

		// Generate a new access token.
		$user = get_user_by( 'id', $user_id );
		$this->send_refresh_token( $user, $request );

		$response = array(
			'success'    => true,
			'statusCode' => 200,
			'code'       => 'jwt_auth_valid_token',
			'message'    => __( 'Token is valid', 'jwt-auth' ),
		);
		return new WP_REST_Response( $response );
	}

	/**
	 * Validates refresh token.
	 *
	 * @param string $refresh_token_cookie The refresh token to validate.
	 * @param string $device The device of the refresh token.
	 * @return int|WP_REST_Response Returns user ID if valid or WP_REST_Response on error.
	 */
	public function validate_refresh_token( $refresh_token_cookie, $device ) {
		$parts = explode( '.', $refresh_token_cookie );
		if ( count( $parts ) !== 2 || empty( intval( $parts[0] ) ) || empty( $parts[1] ) ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_invalid_refresh_token',
					'message'    => __( 'Invalid refresh token', 'jwt-auth' ),
				),
				401
			);
		}

		// The refresh token must match the last issued refresh token for the passed
		// device.
		$user_id             = intval( $parts[0] );
		$user_refresh_tokens = get_user_meta( $user_id, 'jwt_auth_refresh_tokens', true );
		$refresh_token       = $parts[1];

		if ( empty( $user_refresh_tokens[ $device ] ) ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_invalid_refresh_token',
					'message'    => __( 'Invalid refresh token', 'jwt-auth' ),
				),
				401
			);
		} elseif ( $refresh_token !== $user_refresh_tokens[ $device ]['token'] ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_obsolete_refresh_token',
					'message'    => __( 'Refresh token is obsolete', 'jwt-auth' ),
				),
				401
			);
		} elseif ( time() > $user_refresh_tokens[ $device ]['expires'] ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_expired_refresh_token',
					'message'    => __( 'Refresh token has expired', 'jwt-auth' ),
				),
				401
			);
		}

		return $user_id;
	}

	/**
	 * This is our Middleware to try to authenticate the user according to the token sent.
	 *
	 * @param int|bool $user_id User ID if one has been determined, false otherwise.
	 * @return int|bool User ID if one has been determined, false otherwise.
	 */
	public function determine_current_user( $user_id ) {
		/**
		 * This hook only should run on the REST API requests to determine
		 * if the user in the Token (if any) is valid, for any other
		 * normal call ex. wp-admin/.* return the user.
		 *
		 * @since 1.2.3
		 */
		$this->rest_api_slug = get_option( 'permalink_structure' ) ? rest_get_url_prefix() : '?rest_route=/';

		$valid_api_uri = strpos( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), $this->rest_api_slug );

		// Skip validation if not a REST API request or a user was determined already.
		if ( ! $valid_api_uri || $user_id ) {
			return $user_id;
		}

		/**
		 * If the request URI is for validate the token don't do anything,
		 * This avoid double calls to the validate_token function.
		 */
		$validate_uri = strpos( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), 'token/validate' );

		if ( $validate_uri > 0 ) {
			return $user_id;
		}

		$payload = $this->validate_token( false );

		// If $payload is an error response, then the client did not send a token,
		// or the token is invalid, the client uses a different way to authenticate,
		// or the endpoint does not require authentication.
		// Let the endpoint do its regular access checks.
		if ( $this->is_error_response( $payload ) ) {
			return $user_id;
		}

		// Everything is ok here, return the user ID stored in the token.
		return $payload->data->user->id;
	}

	/**
	 * Filter to hook the rest_pre_dispatch, if there is an error in the request
	 * send it, if there is no error just continue with the current request.
	 *
	 * @param mixed           $result Can be anything a normal endpoint can return, or null to not hijack the request.
	 * @param WP_REST_Server  $server Server instance.
	 * @param WP_REST_Request $request The request.
	 *
	 * @return mixed $result
	 */
	public function rest_pre_dispatch( $result, WP_REST_Server $server, WP_REST_Request $request ) {
		if ( $this->is_error_response( $this->jwt_error ) ) {
			return $this->jwt_error;
		}

		if ( empty( $result ) ) {
			return $result;
		}

		return $result;
	}
}

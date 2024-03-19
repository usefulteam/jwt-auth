<?php
/**
 * Setup JWT-Auth.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Psr\Log\LoggerInterface;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

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
	 * The logger interface to use
	 *
	 * @var LoggerInterface
	 */
	private $logger;

	/**
	 * Setup action & filter hooks.
	 *
	 * @param LoggerInterface $logger The logger interface to use.
	 */
	public function __construct( LoggerInterface $logger ) {
		$this->namespace = 'jwt-auth/v1';

		$this->messages = array(
			'jwt_auth_no_auth_header'  => __( 'Authorization header not found.', 'jwt-auth' ),
			'jwt_auth_bad_auth_header' => __( 'Authorization header malformed.', 'jwt-auth' ),
		);

		$this->logger = $logger;
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
		$enable_cors = defined( 'JWT_AUTH_CORS_ENABLE' ) ? JWT_AUTH_CORS_ENABLE : false;

		if ( $enable_cors && ! headers_sent() ) {
			$headers = apply_filters( 'jwt_auth_cors_allow_headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization, Cookie' );

			header( sprintf( 'Access-Control-Allow-Headers: %s', $headers ) );
		}
	}

	/**
	 * Authenticate user either via wp_authenticate or custom auth (e.g: OTP).
	 *
	 * @param string $username The username.
	 * @param string $password The password.
	 * @param mixed $custom_auth The custom auth data (if any).
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
	 *
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

		$refresh_token = $this->retrieve_refresh_token();

		if ( ! empty( $refresh_token ) ) {
			$payload = $this->validate_refresh_token( false );

			// If we receive a REST response, then validation failed.
			if ( $payload instanceof WP_REST_Response ) {
				return $payload;
			}
			$user = get_user_by( 'id', $payload->data->user->id );
			$device = $payload->data->device;
		} else {
			$user = $this->authenticate_user( $username, $password, $custom_auth );
			$device = $request->get_param( 'device' ) ? $request->get_param( 'device' ) : '';
		}

		// If the authentication is failed return error response.
		if ( is_wp_error( $user ) ) {
			$error_code = $user->get_error_code();

			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => $error_code,
					'message'    => strip_tags( $user->get_error_message( $error_code ) ),
					'data'       => array(),
				),
				401
			);
		}

		// Valid credentials, the user exists, let's generate the token.
		$response = $this->generate_token( $user, false );

		// Add the refresh token as a HttpOnly cookie to the response.
		if ( $username && $password ) {
			$refresh_token = $this->send_refresh_token( $user, $device );
		}

		$response['data']['refresh_token'] = $refresh_token;

		return $response;
	}

	/**
	 * Generate access token.
	 *
	 * @param \WP_User $user The WP_User object.
	 * @param bool $return_raw Whether or not to return as raw token string.
	 *
	 * @return WP_REST_Response|string Return as raw token string or as a formatted WP_REST_Response.
	 */
	public function generate_token( $user, $return_raw = true ) {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		$issued_at  = time();
		$not_before = $issued_at;
		$not_before = apply_filters( 'jwt_auth_not_before', $not_before, $issued_at );
		$not_before = apply_filters( 'jwt_auth_token_not_before', $not_before, $issued_at );
		$expire     = $issued_at + ( MINUTE_IN_SECONDS * 10 );
		$expire     = apply_filters( 'jwt_auth_expire', $expire, $issued_at );
		$expire     = apply_filters( 'jwt_auth_token_expire', $expire, $issued_at );

		$payload = array(
			'typ' => 'access',
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
	 * @param string $device Device name. Default empty string
	 *
	 * @return string
	 */
	public function send_refresh_token( \WP_User $user, string $device = ''): string {
		$secret_key    = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		$refresh_token = $this->generate_refresh_token( $user, $device );

		$alg = $this->get_alg();
		$flow = $this->get_flow();

		$payload = JWT::decode( $refresh_token, new Key( $secret_key, $alg ) );

		if ( 'cookie' === $flow ) {
			// Send the refresh token as a HttpOnly cookie in the response.
			setcookie( 'refresh_token', $refresh_token, $payload->exp, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
		}

		// Save new refresh token for the user, replacing the previous one.
		// The refresh token is rotated for the passed device only, not affecting
		// other devices.
		$user_refresh_tokens = get_user_meta( $user->ID, 'jwt_auth_refresh_tokens', true );
		if ( ! is_array( $user_refresh_tokens ) ) {
			$user_refresh_tokens = array();
		}

		$user_refresh_tokens[ $device ] = array(
			'token'   => $refresh_token,
			'expires' => $payload->exp,
		);
		update_user_meta( $user->ID, 'jwt_auth_refresh_tokens', $user_refresh_tokens );

		// Store next expiry for cron_purge_expired_refresh_tokens event.
		$expires_next = $payload->exp;
		foreach ( $user_refresh_tokens as $device ) {
			if ( $device['expires'] < $expires_next ) {
				$expires_next = $device['expires'];
			}
		}
		update_user_meta( $user->ID, 'jwt_auth_refresh_tokens_expires_next', $expires_next );

		return $refresh_token;
	}

	/**
	 * Generate a new refresh token.
	 *
	 * @param \WP_User $user The WP_User object.
	 * @param string $device Device name. Default empty string
	 *
	 * @return string
	 */
	public function generate_refresh_token( \WP_User $user, string $device = '' ): string {
		$secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
		$issued_at  = time();
		$not_before = $issued_at;
		$not_before = apply_filters( 'jwt_auth_refresh_not_before', $not_before, $issued_at );
		$expires    = $issued_at + DAY_IN_SECONDS * 30;
		$expires    = apply_filters( 'jwt_auth_refresh_expire', $expires, $issued_at );

		$payload = array(
			'typ' => 'refresh',
			'iss'  => $this->get_iss(),
			'iat'  => $issued_at,
			'nbf'  => $not_before,
			'exp'  => $expires,
			'data' => array(
				'device' => $device,
				'user'   => array(
					'id' => $user->ID,
				),
			),
		);

		$alg = $this->get_alg();

		return JWT::encode( apply_filters( 'jwt_auth_refresh_token_payload', $payload, $user ), $secret_key, $alg );
	}

	/**
	 * Get the refresh token flow
	 *
	 * @return mixed|null
	 */
	public function get_flow() {
		return apply_filters( 'jwt_auth_flow', 'cookie' );
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
	 *
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
	 * @param bool|WP_REST_Request $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return \stdClass|WP_REST_Response Returns WP_REST_Response or token's $payload.
	 */
	public function validate_token( $return_response_or_request = true ) {
		$return_response = $return_response_or_request instanceof WP_REST_Request ? true : $return_response_or_request;

		/**
		 * Looking for the HTTP_AUTHORIZATION header, if not present just
		 * return the user.
		 */
		$headerkey = apply_filters( 'jwt_auth_authorization_header', 'HTTP_AUTHORIZATION' );
		$auth      = empty( $_SERVER[ $headerkey ] ) ? false : $_SERVER[ $headerkey ];

		// Double check for different auth header string (server dependent).
		if ( ! $auth ) {
			$auth = empty( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? false : $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
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
		list( $token ) = sscanf( $auth, 'Bearer %s' );

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
			$payload = JWT::decode( $token, new Key( $secret_key, $alg ) );

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

			if ( ! isset( $payload->typ ) || $payload->typ !== 'access' ) {
				throw new Exception( __( 'Invalid token type', 'jwt-auth' ) );
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
	 *
	 * @return WP_REST_Response Returns WP_REST_Response.
	 */
	public function refresh_token( \WP_REST_Request $request ) {

		$input_refresh_token = $this->retrieve_refresh_token();

		if ( empty( $input_refresh_token ) ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_no_refresh_token',
					'message'    => __( 'Refresh token not found.', 'jwt-auth' ),
				),
				401
			);
		}

		$payload = $this->validate_refresh_token( false );
		if ( $payload instanceof WP_REST_Response ) {
			return $payload;
		}

		// Generate a new access token.
		$user = get_user_by( 'id', $payload->data->user->id );
		$refresh_token = $this->send_refresh_token( $user, $payload->data->device );

		$flow = $this->get_flow();

		$additional_fields = array();

		if ( $flow !== 'cookie' ) {
			$additional_fields = array(
				'data' => array(
					'refresh_token' => $refresh_token,
				),
			);
		}

		$response = array(
			'success'    => true,
			'statusCode' => 200,
			'code'       => 'jwt_auth_valid_token',
			'message'    => __( 'Token is valid', 'jwt-auth' ),
		);

		return new WP_REST_Response( array_merge( $response, $additional_fields ) );
	}

	/**
	 * Validates refresh token.
	 *
	 * @param bool $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return \stdClass|WP_REST_Response Returns user ID if valid or WP_REST_Response on error.
	 */
	public function validate_refresh_token( $return_response = true ) {

		$refresh_token = $this->retrieve_refresh_token();

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
			$payload = JWT::decode( $refresh_token, new Key( $secret_key, $alg ) );

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

			if ( ! isset( $payload->typ ) || $payload->typ !== 'refresh' ) {
				throw new Exception( __( 'Invalid token type', 'jwt-auth' ) );
			}

			// Check the user id existence in the token.
			if ( ! isset( $payload->data->user->id ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_bad_request',
						'message'    => __( 'User ID not found in the refresh token.', 'jwt-auth' ),
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

			if ( ! isset( $payload->data->device ) ) {
				// Throw invalid token response
				throw new Exception( __( 'Device not found in the refresh token.', 'jwt-auth' ) );
			}

			// The refresh token must match the last issued refresh token for the passed
			// device.
			$user_id             = $payload->data->user->id;
			$user_refresh_tokens = get_user_meta( $user_id, 'jwt_auth_refresh_tokens', true );

			if ( ! is_array( $user_refresh_tokens ) ) {
				$user_refresh_tokens = array();
			}

			$device                    = empty( $payload->data->device ) ? '' : $payload->data->device;
			$last_refresh_token_issued = $user_refresh_tokens[ $device ] ?? null;

			if ( empty( $last_refresh_token_issued ) || $last_refresh_token_issued['token'] !== $refresh_token ) {
				// The refresh token do not match, return error.
				throw new Exception( __( 'Refresh token not found for the device.', 'jwt-auth' ) );
			}

			if ( $last_refresh_token_issued['expires'] < time() ) {
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 401,
						'code'       => 'jwt_auth_obsolete_token',
						'message'    => __( 'Token is obsolete', 'jwt-auth' ),
					),
					401
				);
			}

			// Check extra condition if exists.
			$failed_msg = apply_filters( 'jwt_auth_extra_refresh_token_check', '', $user, $refresh_token, $payload );

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
				'message'    => __( 'Refresh token is valid', 'jwt-auth' ),
				'data'       => array(),
			);

			$response = apply_filters( 'jwt_auth_valid_refresh_token_response', $response, $user, $refresh_token, $payload );

			// Otherwise, return success response.
			return new WP_REST_Response( $response );
		} catch ( Exception $e ) {
			// Something is wrong when trying to decode the token, return error response.
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 401,
					'code'       => 'jwt_auth_invalid_refresh_token',
					'message'    => $e->getMessage(),
					'data'       => array(),
				),
				401
			);
		}
	}

	/**
	 * This is our Middleware to try to authenticate the user according to the token sent.
	 *
	 * @param int|bool $user_id User ID if one has been determined, false otherwise.
	 *
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

		$valid_api_uri = strpos( $_SERVER['REQUEST_URI'], $this->rest_api_slug );

		// Skip validation if not a REST API request or a user was determined already.
		if ( ! $valid_api_uri || $user_id ) {
			return $user_id;
		}

		/**
		 * If the request URI is for validate the token don't do anything,
		 * This avoid double calls to the validate_token function.
		 */
		$validate_uri = strpos( $_SERVER['REQUEST_URI'], 'token/validate' );

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
	 * @param mixed $result Can be anything a normal endpoint can return, or null to not hijack the request.
	 * @param WP_REST_Server $server Server instance.
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

	/**
	 * Retrieves the refresh token based on a flow
	 *
	 * @return string|null
	 */
	private function retrieve_refresh_token(): ?string {
		$flow = $this->get_flow();

		if ( 'body' === $flow ) {
			$_array = $_POST;
		} else if ( 'query' === $flow ) {
			$_array = $_REQUEST;
		} else if ( 'header' === $flow ) {
			$_array = getallheaders() ?: array();
		} else { // default cookie
			$_array = $_COOKIE;
		}

		$refresh_token = $_array['refresh_token'] ?? null;

		return apply_filters( 'jwt_auth_retrieve_refresh_token', $refresh_token, $flow );
	}

}

<?php
/**
 * Setup JWT Auth.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Setup JWT Auth.
 */
class Setup {

	private static $instance;
	public $auth;
	public $devices;

	/**
	 * @var LoggerInterface
	 */
	private $logger;

	/**
	 * Constructs singleton.
	 */
	public static function getInstance() {
		if ( ! isset( self::$instance ) ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'setup_text_domain' ) );

		/**
		 * Allow to define a custom LoggerInterface for the plugin.
		 */
		$logger = apply_filters( 'jwt_auth_logger', new NullLogger() );

		if ( ! $logger instanceof LoggerInterface ) {
			$logger = new NullLogger();
		}
		$this->logger  = $logger;

		$this->auth    = new Auth( $this->logger );
		$this->devices = new Devices( $this->logger );

		add_action( 'rest_api_init', array( $this->auth, 'register_rest_routes' ) );
		add_filter( 'rest_api_init', array( $this->auth, 'add_cors_support' ) );
		add_filter( 'rest_pre_dispatch', array( $this->auth, 'rest_pre_dispatch' ), 10, 3 );
		add_filter( 'determine_current_user', array( $this->auth, 'determine_current_user' ) );

		if ( ! wp_next_scheduled( 'jwt_auth_purge_expired_refresh_tokens' ) ) {
			wp_schedule_event( time(), 'weekly', 'jwt_auth_purge_expired_refresh_tokens' );
		}
		add_action( 'jwt_auth_purge_expired_refresh_tokens', array( $this, 'cron_purge_expired_refresh_tokens' ) );
	}

	/**
	 * Setup textdomain.
	 */
	public function setup_text_domain() {
		load_plugin_textdomain( 'jwt-auth', false, plugin_basename( dirname( __FILE__ ) ) . '/languages' );
	}

	/**
	 * Cleans expired refresh tokens from user accounts.
	 */
	public function cron_purge_expired_refresh_tokens() {
		global $wpdb;

		$this->logger->notice("Cron purge expired refresh tokens.");

		// Retain expired refresh tokens for one month for potential debugging.
		$purge_timestamp = time() - 30 * DAY_IN_SECONDS;

		$user_ids = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta}
			WHERE meta_key = 'jwt_auth_refresh_tokens_expires_next'
			AND meta_value <= %d
		", $purge_timestamp ) );

		foreach ( $user_ids as $user_id ) {
			$user_refresh_tokens = get_user_meta( $user_id, 'jwt_auth_refresh_tokens', true );
			if ( is_array( $user_refresh_tokens ) ) {
				$expires_next = 0;
				foreach ( $user_refresh_tokens as $key => $device ) {
					if ( $device['expires'] <= $purge_timestamp ) {
						unset( $user_refresh_tokens[ $key ] );
					} elseif ( $expires_next === 0 || $device['expires'] <= $expires_next ) {
						$expires_next = $device['expires'];
					}
				}

				if ( $user_refresh_tokens ) {
					update_user_meta( $user_id, 'jwt_auth_refresh_tokens', $user_refresh_tokens );
					update_user_meta( $user_id, 'jwt_auth_refresh_tokens_expires_next', $expires_next );
				} else {
					delete_user_meta( $user_id, 'jwt_auth_refresh_tokens' );
					delete_user_meta( $user_id, 'jwt_auth_refresh_tokens_expires_next' );
				}
			}
		}

		$this->logger->notice("Cron purge expired refresh tokens completed.");
	}

}

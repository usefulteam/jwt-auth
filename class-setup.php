<?php
/**
 * Setup JWT Auth.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

/**
 * Setup JWT Auth.
 */
class Setup {

	private static $instance;
	public $auth;
	public $devices;
	public $updates;

	/**
	 * Constructs singleton.
	 */
	public static function getInstance() {
		if (!isset(self::$instance)) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
		$this->auth    = new Auth();
		$this->devices = new Devices();

		add_action( 'rest_api_init', array( $this->auth, 'register_rest_routes' ) );
		add_filter( 'rest_api_init', array( $this->auth, 'add_cors_support' ) );
		add_filter( 'rest_pre_dispatch', array( $this->auth, 'rest_pre_dispatch' ), 10, 3 );
		add_filter( 'determine_current_user', array( $this->auth, 'determine_current_user' ) );

		// add plugin updates class and filters only in wp-admin
		if ( is_admin() ) {
			require __DIR__ . '/class-update.php';
			$this->updates = new Update();
		}


		if ( ! wp_next_scheduled( 'jwt_auth_purge_expired_refresh_tokens' )) {
			wp_schedule_event( time(), 'weekly', 'jwt_auth_purge_expired_refresh_tokens' );
		}
		add_action( 'jwt_auth_purge_expired_refresh_tokens', array( $this, 'cron_purge_expired_refresh_tokens' ) );

		add_action( 'init', array( $this, 'maybe_schedule_upgrade' ) );
		add_action( 'jwt_auth_upgrade_refresh_tokens', array( $this, 'cron_upgrade_refresh_tokens' ) );
	}

	/**
	 * Version of the stored data. Data stored by earlier versions is updated by
	 * cron_upgrade_refresh_tokens().
	 */
	const DB_VERSION = '3.0.3';

	/**
	 * Number of users handled per run of cron_upgrade_refresh_tokens().
	 */
	const UPGRADE_BATCH_SIZE = 200;

	/**
	 * Schedules the update of stored data after the plugin was updated.
	 */
	public function maybe_schedule_upgrade() {
		if ( version_compare( get_option( 'jwt_auth_db_version', '0' ), self::DB_VERSION, '<' )
			&& ! wp_next_scheduled( 'jwt_auth_upgrade_refresh_tokens' ) ) {
			wp_schedule_single_event( time(), 'jwt_auth_upgrade_refresh_tokens' );
		}
	}

	/**
	 * Deletes refresh tokens that versions before 3.0.3 left behind for devices
	 * that were removed, or whose user changed their password. Refresh tokens
	 * for these devices are already refused, this removes them from the database.
	 *
	 * Runs in batches of users, scheduling itself again until all are done.
	 */
	public function cron_upgrade_refresh_tokens() {
		global $wpdb;

		$last_user_id = (int) get_option( 'jwt_auth_db_upgrade_last_user_id', 0 );

		// Users are selected by meta key, which get_users() cannot do in batches
		// by user id. The query is prepared and read only.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$user_ids = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'jwt_auth_refresh_tokens' AND user_id > %d ORDER BY user_id ASC LIMIT %d",
				$last_user_id,
				self::UPGRADE_BATCH_SIZE
			)
		);

		foreach ( $user_ids as $user_id ) {
			Devices::revoke_unlisted_refresh_tokens( (int) $user_id );
		}

		if ( count( $user_ids ) < self::UPGRADE_BATCH_SIZE ) {
			update_option( 'jwt_auth_db_version', self::DB_VERSION );
			delete_option( 'jwt_auth_db_upgrade_last_user_id' );
			return;
		}

		update_option( 'jwt_auth_db_upgrade_last_user_id', (int) end( $user_ids ), false );
		wp_schedule_single_event( time(), 'jwt_auth_upgrade_refresh_tokens' );
	}

	/**
	 * Cleans expired refresh tokens from user accounts.
	 */
	public function cron_purge_expired_refresh_tokens() {
		global $wpdb;

		// Retain expired refresh tokens for one month for potential debugging.
		$purge_timestamp = time() - 30 * DAY_IN_SECONDS;

		// Users are selected by the value of a meta key, which the metadata API
		// cannot do. The query is prepared and read only.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$user_ids = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta}
			WHERE meta_key = 'jwt_auth_refresh_tokens_expires_next'
			AND meta_value <= %d
		", $purge_timestamp ) );

		foreach ($user_ids as $user_id) {
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
					delete_user_meta(  $user_id, 'jwt_auth_refresh_tokens' );
					delete_user_meta(  $user_id, 'jwt_auth_refresh_tokens_expires_next' );
				}
			}
		}
	}

}

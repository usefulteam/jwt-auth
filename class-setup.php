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
		add_action( 'init', array( $this, 'setup_text_domain' ) );

		$this->auth    = new Auth();
		$this->devices = new Devices();

		add_action( 'rest_api_init', array( $this->auth, 'register_rest_routes' ) );
		add_filter( 'rest_api_init', array( $this->auth, 'add_cors_support' ) );
		add_filter( 'rest_pre_dispatch', array( $this->auth, 'rest_pre_dispatch' ), 10, 3 );
		add_filter( 'determine_current_user', array( $this->auth, 'determine_current_user' ) );
	}

	/**
	 * Setup textdomain.
	 */
	public function setup_text_domain() {
		load_plugin_textdomain( 'jwt-auth', false, plugin_basename( dirname( __FILE__ ) ) . '/languages' );
	}
}

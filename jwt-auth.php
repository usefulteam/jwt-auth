<?php
/**
 * Plugin Name: JWT Auth
 * Plugin URI:  https://github.com/usefulteam/jwt-auth
 * Description: WordPress JWT Authentication.
 * Version:     1.4.2
 * Author:      Useful Team
 * Author URI:  https://usefulteam.com
 * License:     GPL-3.0
 * License URI: https://oss.ninja/gpl-3.0?organization=Useful%20Team&project=jwt-auth
 * Text Domain: jwt-auth
 * Domain Path: /languages
 *
 * @package jwt-auth
 */

defined( 'ABSPATH' ) || die( "Can't access directly" );

// Helper constants.
define( 'JWT_AUTH_PLUGIN_DIR', rtrim( plugin_dir_path( __FILE__ ), '/' ) );
define( 'JWT_AUTH_PLUGIN_URL', rtrim( plugin_dir_url( __FILE__ ), '/' ) );
define( 'JWT_AUTH_PLUGIN_VERSION', '1.4.2' );

// Require composer.
require __DIR__ . '/vendor/autoload.php';

// Require classes.
require __DIR__ . '/class-auth.php';
require __DIR__ . '/class-setup.php';

new JWTAuth\Setup();

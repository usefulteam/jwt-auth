<?php
/**
 * JWT-Auth Plugin Updates Class.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

/**
 * Manage activities related to plugin updates.
 *
 * @author Dominic Vermeulen-Smith https://github.com/dominic-ks
 */
class Update {

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
		add_action( 'in_plugin_update_message-jwt-auth/jwt-auth.php' , array( $this , 'display_update_warnings' ) , 10 , 2 );
		add_action( 'admin_notices' , array( $this , 'display_future_update_warning' ) );
		add_action( 'admin_init', array( 'PAnD', 'init' ) );
	}

	/**
	 * Display update warnings for users updating from 2.x to 3.x.
	 * 
	 * @param array $plugin_data Plugin data.
	 * @param array $response Response.
	 */
	public function display_update_warnings( $plugin_data , $response ) {

		// Only display warning if updating from 2.x to 3.x.
		if ( version_compare( $plugin_data['Version'], '3.0', '>=' ) || version_compare( $plugin_data['new_version'], '3.0', '<' ) ) {
			return;
		}

		ob_start(); ?>

		<style>
			.wrap .notice p:last-of-type::before {
				display: none;
			}
		</style>

		<div style="color: #f00;"><?php echo __( 'IMPORTANT! Please read before updating:', 'jwt-auth' ); ?></div>
		<div style="font-weight: normal; overflow:auto">
			<?php echo __( 'JWT Auth plugin version 3 contains major new features that will change the behaviour of your site.', 'jwt-auth' ); ?> 
			<?php echo __( 'Please review the details of the new version before updating.', 'jwt-auth' ); ?> 
			<br /><br />
			<?php echo __( 'More information can be found on <a href="https://wordpress.org/plugins/jwt-auth/" target="_blank">the plugin page on WordPress.org</a>.', 'jwt-auth' ); ?>
			<div style="clear: left;"></div>
		</div>

		<?php
		$output = ob_get_clean();
		echo $output;

	}

	public function display_future_update_warning() {

		if ( ! \PAnD::is_admin_notice_active( 'jwt-v3-update-warning-1' ) ) {
			return;
		}

		ob_start(); ?>

		<div data-dismissible="jwt-v3-update-warning-1" class="updated notice notice-warning is-dismissible">
			<div style="font-weight: normal; overflow:auto">
				<p><?php echo __( 'Important! An upcoming version of the JWT Auth plugin contains major new features that will change the behaviour of your site.', 'jwt-auth' ); ?>
					<?php echo __( 'More information can be found on <a href="https://wordpress.org/plugins/jwt-auth/" target="_blank">the plugin page on WordPress.org</a>.', 'jwt-auth' ); ?></p>
			</div>
		</div>

		<?php
		$output = ob_get_clean();
		echo $output;

	}
}
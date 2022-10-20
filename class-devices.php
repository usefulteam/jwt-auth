<?php
/**
 * Devices JWT-Auth.
 *
 * @package jwt-auth
 */

namespace JWTAuth;

/**
 * Display the devices connected with token and let remove them in user profile page.
 * Developed by Rodrigo M. Souza https://github.com/pesseba
 */
class Devices {

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {

		add_action( 'show_user_profile', array( $this, 'custom_user_profile_fields' ), 10, 1 );
		add_action( 'edit_user_profile', array( $this, 'custom_user_profile_fields' ), 10, 1 );

		add_action( 'wp_ajax_remove_device', array( $this, 'remove_device' ) );
		add_shortcode( 'jwt_auth_devices', array( $this, 'shortcode_jwt_auth_devices' ) );

		add_action( 'profile_update', array( $this, 'profile_update' ), 10, 2 );
		add_action( 'after_password_reset', array( $this, 'after_password_reset' ), 10, 2 );
		add_action( 'user_register', array( $this, 'after_user_creation' ), 10, 1 );
		
		add_filter( 'jwt_auth_payload', array( $this, 'jwt_auth_payload' ), 10, 2 );
		add_filter( 'jwt_auth_extra_token_check', array( $this, 'check_device_and_pass' ), 10, 4 );
	}

	/**
	 * Filter payload to add device and pass.
	 *
	 * @param array   $payload The token's payload.
	 * @param WP_User $user The user who owns the token.
	 *
	 * @return array $payload The modified token's payload.
	 */
	public function jwt_auth_payload( $payload, $user ) {

		$current_device = isset( $_POST['device'] ) ? $this->sanitize_device_name( sanitize_text_field( $_POST['device'] ) ) : ''; // phpcs:ignore

		// Add device identyfier in user meta if parameter was passed.
		// TODO: considering to use $_SERVER['HTTP_USER_AGENT'] as default value for device in case it is empty.
		if ( ! empty( $current_device ) ) {
			$all_devices = get_user_meta( $user->ID, 'jwt_auth_device', false );

			if ( empty( $all_devices ) || ! in_array( $current_device, $all_devices, true ) ) {
				$data = array(
					'agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ) : '', // phpcs:ignore
					'date'      => date( 'Y-m-d H:i:s', current_time( 'timestamp', 0 ) ),
					'is_mobile' => wp_is_mobile(),
				);

				add_user_meta( $user->ID, 'jwt_auth_device', $current_device, false );
				add_user_meta( $user->ID, $this->sanitize_device_key( $current_device ), $data, true );
			}
		}

		// Add a pass if user doesn't have yet.
		$pass = get_user_meta( $user->ID, 'jwt_auth_pass', true );
		$pass = ( empty( $pass ) ) ? $this->refresh_pass( $user->ID ) : $pass;
		$pass = apply_filters( 'jwt_auth_pass', $pass );

		$payload['data']['user']['device'] = $current_device;
		$payload['data']['user']['pass']   = $pass;

		return $payload;
	}

	/**
	 * Filter token validation to check device and pass.
	 *
	 * @param string  $error_msg The failed message.
	 * @param WP_User $user The user who owns the token.
	 * @param string  $token The token.
	 * @param array   $payload The token's payload.
	 *
	 * @return string The error message if failed, empty string if it passes.
	 */
	public function check_device_and_pass( $error_msg, $user, $token, $payload ) {

		// Check if token has device filled.
		if ( ! empty( $payload->data->user->device ) ) {

			$all_devices = get_user_meta( $user->ID, 'jwt_auth_device', false );

			if ( ! is_array( $all_devices ) || ! in_array( $payload->data->user->device, $all_devices, true ) ) {
				return 'device unnabled';
			}
		}

		// Check if user changed the password.
		$pass = get_user_meta( $user->ID, 'jwt_auth_pass', true );

		if ( $payload->data->user->pass !== $pass ) {
			return 'password changed';
		}

		return '';
	}

	/**
	 * Sanitize the device name.
	 *
	 * @param string $device The device name.
	 * @return string The sanitized device name.
	 */
	private function sanitize_device_name( $device ) {

		$unwanted_chars = array(
			'Š' => 'S',
			'š' => 's',
			'Ž' => 'Z',
			'ž' => 'z',
			'À' => 'A',
			'Á' => 'A',
			'Â' => 'A',
			'Ã' => 'A',
			'Ä' => 'A',
			'Å' => 'A',
			'Æ' => 'A',
			'Ç' => 'C',
			'È' => 'E',
			'É' => 'E',
			'Ê' => 'E',
			'Ë' => 'E',
			'Ì' => 'I',
			'Í' => 'I',
			'Î' => 'I',
			'Ï' => 'I',
			'Ñ' => 'N',
			'Ò' => 'O',
			'Ó' => 'O',
			'Ô' => 'O',
			'Õ' => 'O',
			'Ö' => 'O',
			'Ø' => 'O',
			'Ù' => 'U',
			'Ú' => 'U',
			'Û' => 'U',
			'Ü' => 'U',
			'Ý' => 'Y',
			'Þ' => 'B',
			'ß' => 'Ss',
			'à' => 'a',
			'á' => 'a',
			'â' => 'a',
			'ã' => 'a',
			'ä' => 'a',
			'å' => 'a',
			'æ' => 'a',
			'ç' => 'c',
			'è' => 'e',
			'é' => 'e',
			'ê' => 'e',
			'ë' => 'e',
			'ì' => 'i',
			'í' => 'i',
			'î' => 'i',
			'ï' => 'i',
			'ð' => 'o',
			'ñ' => 'n',
			'ò' => 'o',
			'ó' => 'o',
			'ô' => 'o',
			'õ' => 'o',
			'ö' => 'o',
			'ø' => 'o',
			'ù' => 'u',
			'ú' => 'u',
			'û' => 'u',
			'ý' => 'y',
			'þ' => 'b',
			'ÿ' => 'y',
		);

		$device = strtr( $device, $unwanted_chars );
		$device = preg_replace( '/[^a-z0-9 ]/i', '', $device );

		return $device;
	}

	/**
	 * Sanitize the device key.
	 *
	 * @param string $key The device key.
	 * @return string The sanitized device key.
	 */
	private function sanitize_device_key( $key ) {
		return 'jwt_auth_device_' . str_replace( ' ', '_', $this->sanitize_device_name( $key ) );
	}

	/**
	 * Fires immediately after an existing user is updated.
	 *
	 * @since 2.0.0
	 *
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data Object containing user's data prior to update.
	 */
	public function profile_update( $user_id, $old_user_data ) {

		$user = get_user_by( 'id', $user_id );

		if ( $user->user_pass !== $old_user_data->user_pass ) {

			$this->block_all_tokens( $user_id );
		}
	}

	/**
	 * Fires after the user's password is reset.
	 *
	 * @since 4.4.0
	 *
	 * @param WP_User $user     The user.
	 * @param string  $new_pass New user password.
	 */
	public function after_password_reset( $user, $new_pass ) {

		$this->block_all_tokens( $user->ID );
	}
	
	/**
	 * Fires after the user' is created
	 *
	 * @since 2.0.0
	 *
	 * @param int 		$user_id    The user ID.
	 */
	public function after_user_creation( $user_id ) {
		
		$this->refresh_pass( $user_id );
	}

	/**
	 * Block all access tokens.
	 *
	 * @param int $user_id The user id.
	 */
	private function block_all_tokens( $user_id ) {

		// Clear devices list with access.
		delete_user_meta( $user_id, 'jwt_auth_device' );

		global $wpdb;

		// ! Can we not using a direct database call? Because it is discouraged in wpcs.
		// This is because performance. The key jwt_auth_device_% is has generic key name, so this is necessary. The query uses prepare() to avoid insections anyway
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM $wpdb->usermeta WHERE user_id = %d AND meta_key LIKE %s",
				$user_id,
				'jwt_auth_device_%'
			)
		);

		// Add a hash for the new password.
		$this->refresh_pass( $user_id );
	}

	/**
	 * Refresh the pass value in user meta.
	 *
	 * @param int $user_id The user id.
	 */
	private function refresh_pass( $user_id ) {
		$pass = (string) md5( uniqid( wp_rand(), true ));
		if(!empty(update_user_meta( $user_id, 'jwt_auth_pass', $pass ) )){
			return $pass;
		}
		return '';
	}

	// -------------------------------------------------------------------------------------------------------

	/**
	 * Remove the device from token access.
	 */
	public function remove_device() {

		$nonce = isset( $_POST['nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nonce'] )) : ''; 
		$device  = isset( $_POST['device'] ) ? sanitize_text_field( $_POST['device'] ) : ''; // phpcs:ignore
		$user_id = isset( $_POST['user_id'] ) && is_numeric( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : 0; // phpcs:ignore
		
		if(!wp_verify_nonce( $nonce, 'jwt_auth_remove_device_'.$user_id)){
			wp_send_json_error();
			wp_die();
			return;
		}

		if ( delete_user_meta( $user_id, 'jwt_auth_device', $device ) ) {
			delete_user_meta( $user_id, $this->sanitize_device_key( $device ) );
			wp_send_json_success();
		} else {
			wp_send_json_error();
		}

		wp_die();
	}

	/**
	 * Show custom user profile fields.
	 *
	 * @param WP_User $profileuser The current WP_User object.
	 */
	public function custom_user_profile_fields( $profileuser ) {

		// If is current user's profile (profile.php).
		if ( defined( 'IS_PROFILE_PAGE' ) && IS_PROFILE_PAGE ) {
			$user_id = get_current_user_id();
		} elseif ( ! empty( $_GET['user_id'] ) && is_numeric( $_GET['user_id'] ) ) { // phpcs:ignore
			// If is another user's profile page.
			$user_id = absint( $_GET['user_id'] ); // phpcs:ignore
		} else {
			// Otherwise something is wrong.
			die( 'No user id defined.' );
		}

		?>
		<h2><?php echo wp_kses( __( 'Connected Devices', 'jwt-auth' ) , 'post' ); ?></h2>
		<div id="jwt_auth_devices" style="width:33%">
			<?php echo do_shortcode( '[jwt_auth_devices user_id=' . $user_id . ']' ); ?>
		</div>
		<?php

	}

	/**
	 * Shortcode to display the user ranking position.
	 *
	 * @param array $atts The shortcode attributes.
	 */
	public function shortcode_jwt_auth_devices( $atts ) {

		if ( ! is_admin() ) {
			return '';
		}

		$atts = shortcode_atts(
			array(
				'user_id' => get_current_user_id(),
			),
			$atts,
			'jwt_auth_devices'
		);

		$user_id = absint( $atts['user_id'] );

		if ( get_current_user_id() !== $user_id ) {
			if ( ! current_user_can( 'administrator' ) ) {
				return '';
			}
		}

		$devices = get_user_meta( $user_id, 'jwt_auth_device', false );

		if ( count( $devices ) === 0 ) {
			return '<p>' . __( 'You have no devices connected', 'jwt-auth' ) . '</p>';
		}

		ob_start();
		?>

		<style>
		.device_area {margin: 0 -5px;}
		.device_area:after {
			content: "";
			display: table;
			clear: both;
		}
		.device_column {
			float: left;
			width: 200px;
			padding: 10px 10px;
			box-sizing: border-box;
		}
		.device_card {
			box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2);
			padding: 16px;
			text-align: center;
			background-color: #f1f1f1;
		}
		.device_title {
			font-size:1vw;
		}
		.device_date {
			font-size:0.7vw;
		}
		.device_agent {
			font-size:0.5vw;
		}
		</style>

		<script type="text/javascript">
		function jwt_auth_remove_device(user_id, device_name, index) {

			if (confirm('Are you sure you want to remove this device access?')) {

				var totalDevices = <?php echo count( $devices ); ?>;

				for (var i=0; i < totalDevices; i++) {
					var btn = document.getElementById("jwt_auth_remove_button-"+i);
					if(btn!=null) { btn.disabled=true; }
				}

				var data = {
					'action': 'remove_device',
					'user_id': user_id,
					'device': device_name,
					'nonce': '<?php echo wp_kses( wp_create_nonce('jwt_auth_remove_device_'.$user_id ) , 'post' ); ?>',
				};

				jQuery.post(ajaxurl, data, function(response) {

					if (response['success'] == true) {

						var elem = document.getElementById("jwt_auth_device-"+index);
						elem.parentNode.removeChild(elem);

						for(var i=0; i < totalDevices; i++){
							var btn = document.getElementById("jwt_auth_remove_button-"+i);
							if(btn!=null) { btn.disabled=false; }
						}						

					} else {

						alert("<?php echo wp_kses( __( "Ops... device couldn't be removed!", 'jwt-auth' ) , 'post' ); ?>");						
					}

				});
			}
		}
		</script>

		<div id="jwt_auth_devices" class="device_area">	

			<?php
			$line = false;

			$total_devices = count( $devices );

			for ( $i = 0; $i < $total_devices; ++$i ) {

				$device      = $devices[ $i ];
				$title       = preg_replace( '/(\S{15})(?=\S)/', '$1 ', $device );
				$title       = ( strlen( $title ) > 30 ) ? substr( $title, 0, 27 ) . '...' : $title;
				$device_data = (array) get_user_meta( $user_id, $this->sanitize_device_key( $device ), true );
				$icon        = ( $device_data['is_mobile'] ) ? 'dashicons-smartphone' : 'dashicons-laptop';
				$date        = $device_data['date'];
				$agent       = $device_data['agent'];
				$agent       = preg_replace( '/(\S{15})(?=\S)/', '$1 ', $agent );

				?>

				<div class="device_column" id="jwt_auth_device-<?php echo esc_attr( $i ); ?>">
					<div class="device_card">
						<span class="dashicons <?php echo esc_attr( $icon ); ?>" style="font-size:28px; color:grey;" ></span>
						<p class="device_title"><h3><?php echo esc_html( $title ); ?></h3></p>
						<p class="device_date"><?php echo esc_html( $date ); ?></p>
						<p class="device_agent"><?php echo esc_html( $agent ); ?></p>

						<?php
						echo '
							<input id="jwt_auth_remove_button-' . esc_attr( $i ) .
							'" class="button wp-generate-pw' .
							'" type="button" value="' . esc_attr( __( 'Remove', 'jwt-auth' )) .
							'" onclick="jwt_auth_remove_device(\'' . esc_attr( $user_id ) . '\',\'' . esc_attr( $device ) . '\',\'' . esc_attr( $i ) . '\' )" />
						';
						?>
					</div>
				</div>
				<?php
			}
			?>

		</div>		
		</br>

		<?php

		return ob_get_clean();
	}
}

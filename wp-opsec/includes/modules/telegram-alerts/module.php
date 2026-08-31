<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Real-time Telegram notification for high-severity events.
 *
 * The actual send call (wpopsec_maybe_telegram_alert()) lives in the
 * mu-loader, not here — it has to run inline inside wpopsec_log_event()
 * itself, because a real block calls wp_die() immediately afterwards at
 * mu-plugin time, before regular plugins (this module included) have even
 * loaded. This module is just the admin UI and settings around that.
 */
class WPOpsec_Module_Telegram_Alerts {

	const API = 'https://api.telegram.org/bot';

	public static function activate() {}
	public static function deactivate() {}

	public static function register() {
		add_action( 'admin_post_wpopsec_tg_save_settings', array( __CLASS__, 'handle_save_settings' ) );
		add_action( 'admin_post_wpopsec_tg_test', array( __CLASS__, 'handle_test' ) );
		add_action( 'admin_post_wpopsec_tg_detect_chat', array( __CLASS__, 'handle_detect_chat' ) );

		return __CLASS__;
	}

	private static function api_call( $token, $method, $args = array() ) {
		$response = wp_remote_post(
			self::API . rawurlencode( $token ) . '/' . $method,
			array( 'timeout' => 10, 'body' => $args )
		);

		if ( is_wp_error( $response ) ) {
			return array( 'ok' => false, 'error' => $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['ok'] ) ) {
			return array( 'ok' => false, 'error' => $body['description'] ?? 'Unknown Telegram API error' );
		}

		return array( 'ok' => true, 'result' => $body['result'] );
	}


	public static function handle_save_settings() {
		check_admin_referer( 'wpopsec_tg_save_settings' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		update_option( 'wpopsec_telegram_enabled', isset( $_POST['enabled'] ) );

		$token = isset( $_POST['bot_token'] ) ? trim( wp_unslash( $_POST['bot_token'] ) ) : '';
		update_option( 'wpopsec_telegram_bot_token', $token );

		$chat_id = isset( $_POST['chat_id'] ) ? trim( wp_unslash( $_POST['chat_id'] ) ) : '';
		update_option( 'wpopsec_telegram_chat_id', $chat_id );

		$threshold = isset( $_POST['threshold'] ) ? max( 1, min( 20, (int) $_POST['threshold'] ) ) : 15;
		update_option( 'wpopsec_telegram_threshold', $threshold );

		wp_safe_redirect( add_query_arg( 'saved', '1', wp_get_referer() ) );
		exit;
	}

	public static function handle_test() {
		check_admin_referer( 'wpopsec_tg_test' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$token   = trim( (string) get_option( 'wpopsec_telegram_bot_token', '' ) );
		$chat_id = trim( (string) get_option( 'wpopsec_telegram_chat_id', '' ) );

		if ( '' === $token || '' === $chat_id ) {
			wp_safe_redirect( add_query_arg( 'test', 'missing', wp_get_referer() ) );
			exit;
		}

		$site = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
		$host = wp_parse_url( get_option( 'siteurl' ), PHP_URL_HOST ) ?: '';
		$result = self::api_call(
			$token,
			'sendMessage',
			array(
				'chat_id'    => $chat_id,
				'parse_mode' => 'HTML',
				'text'       => sprintf(
					"<b>%s</b>%s\nWP Opsec test message — if you can read this, alerts are wired up correctly.",
					esc_html( $site ),
					$host ? ' (' . esc_html( $host ) . ')' : ''
				),
			)
		);

		wp_safe_redirect( add_query_arg( 'test', $result['ok'] ? 'ok' : rawurlencode( 'fail:' . $result['error'] ), wp_get_referer() ) );
		exit;
	}

	/**
	 * Reads the bot's recent updates and pulls the chat id from whoever
	 * most recently messaged it — saves the admin from finding their
	 * numeric Telegram chat id by hand.
	 */
	public static function handle_detect_chat() {
		check_admin_referer( 'wpopsec_tg_detect_chat' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Forbidden', 403 );
		}

		$token = trim( (string) get_option( 'wpopsec_telegram_bot_token', '' ) );
		if ( '' === $token ) {
			wp_safe_redirect( add_query_arg( 'detect', 'missing', wp_get_referer() ) );
			exit;
		}

		$result = self::api_call( $token, 'getUpdates' );
		if ( ! $result['ok'] || empty( $result['result'] ) ) {
			wp_safe_redirect( add_query_arg( 'detect', 'none', wp_get_referer() ) );
			exit;
		}

		$latest = end( $result['result'] );
		$chat   = $latest['message']['chat'] ?? $latest['message_reaction']['chat'] ?? null;

		if ( empty( $chat['id'] ) ) {
			wp_safe_redirect( add_query_arg( 'detect', 'none', wp_get_referer() ) );
			exit;
		}

		update_option( 'wpopsec_telegram_chat_id', (string) $chat['id'] );
		update_option( 'wpopsec_telegram_chat_name', $chat['username'] ?? $chat['first_name'] ?? '', false );

		wp_safe_redirect( add_query_arg( 'detect', 'ok', wp_get_referer() ) );
		exit;
	}

	public static function render_page() {
		$enabled    = get_option( 'wpopsec_telegram_enabled', false );
		$token      = (string) get_option( 'wpopsec_telegram_bot_token', '' );
		$chat_id    = (string) get_option( 'wpopsec_telegram_chat_id', '' );
		$chat_name  = (string) get_option( 'wpopsec_telegram_chat_name', '' );
		$threshold  = (int) get_option( 'wpopsec_telegram_threshold', 15 );

		WPOpsec_UI::open( 'telegram-alerts' );

		if ( isset( $_GET['saved'] ) ) {
			WPOpsec_UI::notice( 'success', 'Settings saved.' );
		}
		if ( isset( $_GET['test'] ) ) {
			if ( 'ok' === $_GET['test'] ) {
				WPOpsec_UI::notice( 'success', 'Test message sent — check Telegram.' );
			} elseif ( 'missing' === $_GET['test'] ) {
				WPOpsec_UI::notice( 'warning', 'Set a bot token and chat ID first.' );
			} else {
				WPOpsec_UI::notice( 'error', 'Telegram rejected the test message: ' . esc_html( sanitize_text_field( wp_unslash( str_replace( 'fail:', '', $_GET['test'] ) ) ) ) );
			}
		}
		if ( isset( $_GET['detect'] ) ) {
			if ( 'ok' === $_GET['detect'] ) {
				WPOpsec_UI::notice( 'success', 'Chat ID detected and saved.' );
			} elseif ( 'missing' === $_GET['detect'] ) {
				WPOpsec_UI::notice( 'warning', 'Set a bot token first.' );
			} else {
				WPOpsec_UI::notice( 'warning', 'No messages found. Send anything to your bot on Telegram, then try again.' );
			}
		}

		WPOpsec_UI::tiles(
			array(
				array(
					'icon'  => $enabled ? 'yes-alt' : 'warning',
					'tone'  => $enabled ? 'good' : 'warn',
					'value' => $enabled ? 'Enabled' : 'Disabled',
					'label' => 'Telegram alerts',
				),
				array(
					'icon'  => 'filter',
					'tone'  => 'quiet',
					'value' => '> ' . $threshold,
					'label' => 'severity threshold',
				),
				array(
					'icon'  => $chat_id ? 'yes-alt' : 'warning',
					'tone'  => $chat_id ? 'good' : 'warn',
					'value' => $chat_id ? 'Set' : 'Not set',
					'label' => $chat_name ? 'chat: ' . $chat_name : 'chat ID',
				),
			)
		);

		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wpopsec_tg_save_settings' ); ?>
			<input type="hidden" name="action" value="wpopsec_tg_save_settings">

			<?php WPOpsec_UI::section( 'Telegram bot', 'testimonial' ); ?>
				<?php
				WPOpsec_UI::row(
					'Enabled',
					function () use ( $enabled ) {
						?>
						<label><input type="checkbox" name="enabled" <?php checked( $enabled ); ?>> Send a Telegram message when an event exceeds the threshold below</label>
						<?php
					}
				);

				WPOpsec_UI::row(
					'Bot token',
					function () use ( $token ) {
						?>
						<input type="password" name="bot_token" value="<?php echo esc_attr( $token ); ?>" style="width:100%;max-width:420px" autocomplete="off">
						<?php
					},
					'From <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> on Telegram — message it <code>/newbot</code> to create one.'
				);

				WPOpsec_UI::row(
					'Chat ID',
					function () use ( $chat_id ) {
						?>
						<input type="text" name="chat_id" value="<?php echo esc_attr( $chat_id ); ?>" style="width:16em">
						<?php
					},
					'Send any message to your bot on Telegram first, then use "Detect chat ID" below rather than finding this number by hand.'
				);

				WPOpsec_UI::row(
					'Threshold',
					function () use ( $threshold ) {
						?>
						Alert on events with severity greater than <input type="number" name="threshold" value="<?php echo esc_attr( $threshold ); ?>" min="1" max="20" style="width:5em">
						<?php
					},
					'18+ means something already happened (a core file changed, a rogue admin account); 14&ndash;17 is a serious exploitation attempt that was stopped. The Event Log records everything regardless of this setting — this only controls what interrupts you in real time.'
				);
				?>
			<?php WPOpsec_UI::section_end(); ?>

			<?php submit_button( 'Save settings' ); ?>
		</form>

		<div class="wpopsec-actions" style="margin-top:14px">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_tg_detect_chat' ); ?>
				<input type="hidden" name="action" value="wpopsec_tg_detect_chat">
				<?php submit_button( 'Detect chat ID', 'secondary', 'submit', false ); ?>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'wpopsec_tg_test' ); ?>
				<input type="hidden" name="action" value="wpopsec_tg_test">
				<?php submit_button( 'Send test message', 'secondary', 'submit', false ); ?>
			</form>
		</div>
		<?php
		WPOpsec_UI::close();
	}
}

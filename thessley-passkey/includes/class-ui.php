<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Presentation helpers for the Thessley Passkey screens.
 *
 * A deliberately small copy of Thessley Security Hardening's Thessley_UI:
 * only the pieces this plugin uses (page frame, notices, section cards,
 * badges and labelled rows). Styling comes from assets/admin.css, which is
 * shipped with the plugin, so nothing here depends on the hardening plugin
 * being installed.
 */
class Thessley_Passkey_UI {

	public static function open() {
		?>
		<div class="wrap thessley">
			<div class="thessley-head">
				<span class="thessley-head__icon dashicons dashicons-smartphone"></span>
				<div>
					<h1>Thessley Passkey</h1>
					<p class="thessley-head__desc">Passwordless sign-in via the Thessley Passkey Android app — scan a QR code or tap a link, confirmed with the device's own biometric lock.</p>
				</div>
			</div>
		<?php
	}

	public static function close() {
		echo '</div>';
	}

	/**
	 * @param string $type success|warning|error|info
	 */
	public static function notice( $type, $message, $allow_html = false ) {
		$icons = array(
			'success' => 'yes-alt',
			'warning' => 'warning',
			'error'   => 'dismiss',
			'info'    => 'info-outline',
		);
		$icon = $icons[ $type ] ?? 'info-outline';
		?>
		<div class="thessley-notice thessley-notice--<?php echo esc_attr( $type ); ?>">
			<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
			<div><?php echo $allow_html ? wp_kses_post( $message ) : esc_html( $message ); ?></div>
		</div>
		<?php
	}

	public static function section( $title, $icon = '', $subtitle = '' ) {
		?>
		<section class="thessley-section">
			<header class="thessley-section__head">
				<?php if ( $icon ) : ?>
					<span class="dashicons dashicons-<?php echo esc_attr( $icon ); ?>"></span>
				<?php endif; ?>
				<h2><?php echo esc_html( $title ); ?></h2>
				<?php if ( $subtitle ) : ?>
					<span class="thessley-section__sub"><?php echo esc_html( $subtitle ); ?></span>
				<?php endif; ?>
			</header>
			<div class="thessley-section__body">
		<?php
	}

	public static function section_end() {
		echo '</div></section>';
	}

	/**
	 * Status badge.
	 *
	 * @param string $tone good|warn|bad|quiet
	 */
	public static function badge( $text, $tone = 'quiet', $icon = '' ) {
		printf(
			'<span class="thessley-badge thessley-badge--%s">%s%s</span>',
			esc_attr( $tone ),
			$icon ? '<span class="dashicons dashicons-' . esc_attr( $icon ) . '"></span>' : '',
			esc_html( $text )
		);
	}

	/** A labelled row inside a settings card. */
	public static function row( $label, $body_cb, $help = '' ) {
		?>
		<div class="thessley-row">
			<div class="thessley-row__label"><?php echo esc_html( $label ); ?></div>
			<div class="thessley-row__field">
				<?php call_user_func( $body_cb ); ?>
				<?php if ( $help ) : ?>
					<p class="thessley-help"><?php echo wp_kses_post( $help ); ?></p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}

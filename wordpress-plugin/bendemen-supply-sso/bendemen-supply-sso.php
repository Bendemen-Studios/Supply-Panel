<?php
/**
 * Plugin Name: Bendemen Supply Panel SSO
 * Description: Beveiligde eenmalige login vanuit Bendemen Supply Panel naar de WooCommerce-betaalpagina.
 * Version: 1.0.0
 * Author: Bendemen Studios
 */
if (!defined('ABSPATH')) exit;

add_action('rest_api_init', function () {
    register_rest_route('bendemen-sso/v1', '/login', [
        'methods' => 'GET',
        'callback' => 'bendemen_supply_sso_login',
        'permission_callback' => '__return_true',
    ]);
});

function bendemen_supply_sso_login(WP_REST_Request $request) {
    if (!defined('BENDEMEN_SUPPLY_SSO_SECRET') || strlen(BENDEMEN_SUPPLY_SSO_SECRET) < 32) {
        return new WP_Error('sso_not_configured', 'SSO is niet geconfigureerd.', ['status' => 503]);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_Error('woocommerce_unavailable', 'WooCommerce is niet beschikbaar.', ['status' => 503]);
    }
    $token = (string) $request->get_param('token');
    $parts = explode('.', $token);
    if (count($parts) !== 2) return new WP_Error('invalid_token', 'Ongeldige toegangscode.', ['status' => 401]);
    $payload_json = base64_decode(strtr($parts[0], '-_', '+/'));
    $expected = hash_hmac('sha256', $parts[0], BENDEMEN_SUPPLY_SSO_SECRET);
    if (!$payload_json || !hash_equals($expected, $parts[1])) {
        return new WP_Error('invalid_signature', 'Ongeldige toegangscode.', ['status' => 401]);
    }
    $claims = json_decode($payload_json, true);
    if (!is_array($claims) || empty($claims['order_id']) || empty($claims['customer_id']) ||
        empty($claims['nonce']) || empty($claims['exp']) || (int) $claims['exp'] < time() ||
        (int) $claims['exp'] > time() + 180) {
        return new WP_Error('expired_token', 'De betaallink is verlopen. Open de bestelling opnieuw.', ['status' => 401]);
    }
    $nonce_key = 'bendemen_sso_' . hash('sha256', (string) $claims['nonce']);
    if (get_transient($nonce_key)) return new WP_Error('token_used', 'Deze betaallink is al gebruikt. Open de bestelling opnieuw.', ['status' => 401]);
    $order = wc_get_order(absint($claims['order_id']));
    if (!$order || (int) $order->get_customer_id() !== (int) $claims['customer_id']) {
        return new WP_Error('order_mismatch', 'De bestelling hoort niet bij dit account.', ['status' => 403]);
    }
    if (!$order->needs_payment()) return new WP_Error('payment_not_required', 'Voor deze bestelling is geen betaling meer nodig.', ['status' => 409]);
    $user = get_user_by('id', (int) $claims['customer_id']);
    if (!$user || !in_array('customer', (array) $user->roles, true)) {
        return new WP_Error('customer_not_found', 'Het WooCommerce-klantaccount is niet gevonden.', ['status' => 404]);
    }
    set_transient($nonce_key, 1, 5 * MINUTE_IN_SECONDS);
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, false, is_ssl());
    do_action('wp_login', $user->user_login, $user);
    $url = $order->get_checkout_payment_url();
    if (!$url) return new WP_Error('payment_url_missing', 'WooCommerce heeft geen betaalpagina beschikbaar.', ['status' => 409]);
    return new WP_REST_Response(null, 302, ['Location' => $url, 'Cache-Control' => 'no-store, no-cache, must-revalidate']);
}

<?php
/**
 * Plugin Name: Bendemen Supply Panel SSO
 * Description: Beveiligde eenmalige login vanuit Bendemen Supply Panel naar de WooCommerce-betaalpagina.
 * Version: 1.1.0
 * Author: Bendemen Studios
 */
if (!defined('ABSPATH')) exit;

define('BENDEMEN_SUPPLY_SSO_OPTION', 'bendemen_supply_sso_secret');

function bendemen_supply_sso_generate_secret() {
    return bin2hex(random_bytes(32));
}

function bendemen_supply_sso_get_secret() {
    if (defined('BENDEMEN_SUPPLY_SSO_SECRET') && BENDEMEN_SUPPLY_SSO_SECRET !== '') {
        return (string) BENDEMEN_SUPPLY_SSO_SECRET;
    }

    $secret = (string) get_option(BENDEMEN_SUPPLY_SSO_OPTION, '');
    if ($secret === '') {
        $secret = bendemen_supply_sso_generate_secret();
        add_option(BENDEMEN_SUPPLY_SSO_OPTION, $secret, '', false);
        $secret = (string) get_option(BENDEMEN_SUPPLY_SSO_OPTION, $secret);
    }
    return $secret;
}

add_action('admin_menu', function () {
    add_submenu_page(
        'woocommerce',
        'Bendemen Supply SSO',
        'Supply Panel SSO',
        'manage_woocommerce',
        'bendemen-supply-sso',
        'bendemen_supply_sso_render_settings'
    );
});

add_action('admin_post_bendemen_supply_sso_regenerate', function () {
    if (!current_user_can('manage_woocommerce')) {
        wp_die(esc_html__('Je hebt geen toestemming om SSO-instellingen te beheren.', 'bendemen-supply-sso'), 403);
    }
    check_admin_referer('bendemen_supply_sso_regenerate');

    if (defined('BENDEMEN_SUPPLY_SSO_SECRET')) {
        wp_safe_redirect(add_query_arg(
            ['page' => 'bendemen-supply-sso', 'secret_managed' => 'constant'],
            admin_url('admin.php')
        ));
        exit;
    }

    update_option(BENDEMEN_SUPPLY_SSO_OPTION, bendemen_supply_sso_generate_secret(), false);
    wp_safe_redirect(add_query_arg(
        ['page' => 'bendemen-supply-sso', 'secret_regenerated' => '1'],
        admin_url('admin.php')
    ));
    exit;
});

function bendemen_supply_sso_render_settings() {
    if (!current_user_can('manage_woocommerce')) return;

    $secret = bendemen_supply_sso_get_secret();
    $constant_managed = defined('BENDEMEN_SUPPLY_SSO_SECRET');
    ?>
    <div class="wrap">
        <h1>Bendemen Supply Panel SSO</h1>
        <p>Deze geheime sleutel beveiligt de eenmalige login vanuit Supply Panel naar WooCommerce.</p>
        <?php if (isset($_GET['secret_regenerated'])) : ?>
            <div class="notice notice-success is-dismissible"><p>Er is een nieuwe SSO-secret aangemaakt. Werk ook <code>WC_SSO_SECRET</code> bij in Supply Panel.</p></div>
        <?php endif; ?>
        <?php if (isset($_GET['secret_managed']) && $constant_managed) : ?>
            <div class="notice notice-warning"><p>De secret wordt beheerd via <code>BENDEMEN_SUPPLY_SSO_SECRET</code> in wp-config.php. Pas die constante aan om de sleutel te wijzigen.</p></div>
        <?php endif; ?>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><label for="bendemen-supply-sso-secret">SSO Secret</label></th>
                <td>
                    <input type="password" id="bendemen-supply-sso-secret" class="regular-text"
                        value="<?php echo esc_attr($secret); ?>" autocomplete="new-password" readonly />
                    <button type="button" class="button" id="bendemen-supply-sso-toggle">Tonen</button>
                    <button type="button" class="button" id="bendemen-supply-sso-copy">Kopiëren</button>
                    <p class="description">Gebruik exact dezelfde secret bij Supply Panel. Deel deze sleutel nooit met klanten.</p>
                </td>
            </tr>
        </table>

        <?php if (!$constant_managed) : ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"
                onsubmit="return confirm('Weet je zeker dat je een nieuwe SSO-secret wilt maken? Supply Panel SSO werkt pas weer nadat je WC_SSO_SECRET daar hebt bijgewerkt.');">
                <input type="hidden" name="action" value="bendemen_supply_sso_regenerate" />
                <?php wp_nonce_field('bendemen_supply_sso_regenerate'); ?>
                <?php submit_button('Nieuwe secret genereren', 'secondary'); ?>
            </form>
        <?php endif; ?>

        <hr />
        <h2>Supply Panel configuratie</h2>
        <p>Kopieer de secret naar de environment variables van Supply Panel:</p>
        <p><code>WC_SSO_URL=https://jouw-webshop-domein.nl</code></p>
        <p><code>WC_SSO_SECRET=jouw_gekopieerde_secret</code></p>
    </div>
    <script>
    (function () {
        const field = document.getElementById('bendemen-supply-sso-secret');
        const toggle = document.getElementById('bendemen-supply-sso-toggle');
        const copy = document.getElementById('bendemen-supply-sso-copy');
        if (!field || !toggle || !copy) return;

        toggle.addEventListener('click', function () {
            const visible = field.type === 'text';
            field.type = visible ? 'password' : 'text';
            toggle.textContent = visible ? 'Tonen' : 'Verbergen';
        });

        copy.addEventListener('click', async function () {
            try {
                await navigator.clipboard.writeText(field.value);
                copy.textContent = 'Gekopieerd!';
            } catch (error) {
                field.type = 'text';
                field.focus();
                field.select();
                document.execCommand('copy');
                copy.textContent = 'Gekopieerd!';
            }
            window.setTimeout(function () { copy.textContent = 'Kopiëren'; }, 1800);
        });
    }());
    </script>
    <?php
}

add_action('rest_api_init', function () {
    register_rest_route('bendemen-sso/v1', '/login', [
        'methods' => 'GET',
        'callback' => 'bendemen_supply_sso_login',
        'permission_callback' => '__return_true',
    ]);
});

function bendemen_supply_sso_login(WP_REST_Request $request) {
    $secret = bendemen_supply_sso_get_secret();
    if (strlen($secret) < 32) {
        return new WP_Error('sso_not_configured', 'SSO is niet geconfigureerd.', ['status' => 503]);
    }
    if (!function_exists('wc_get_order')) {
        return new WP_Error('woocommerce_unavailable', 'WooCommerce is niet beschikbaar.', ['status' => 503]);
    }
    $token = (string) $request->get_param('token');
    $parts = explode('.', $token);
    if (count($parts) !== 2) return new WP_Error('invalid_token', 'Ongeldige toegangscode.', ['status' => 401]);
    $payload_json = base64_decode(strtr($parts[0], '-_', '+/'));
    $expected = hash_hmac('sha256', $parts[0], $secret);
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

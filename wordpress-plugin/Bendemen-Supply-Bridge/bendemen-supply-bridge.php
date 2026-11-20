<?php
/**
 * Plugin Name: Bendemen Supply Bridge
 * Description: Beveiligde interne WooCommerce-verbinding voor Bendemen Supply Panel.
 * Version: 1.0.0
 * Author: Bendemen
 * Requires Plugins: woocommerce
 */

if (!defined('ABSPATH')) exit;

final class Bendemen_Supply_Bridge {
    const VERSION = '1.0.0';
    const OPTION = 'bendemen_supply_bridge_secret';
    const REST_NS = 'bendemen-supply/v1';

    public static function boot() {
        add_action('rest_api_init', [__CLASS__, 'register_routes']);
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        register_activation_hook(__FILE__, [__CLASS__, 'activate']);
    }

    public static function activate() {
        if (!get_option(self::OPTION)) {
            add_option(self::OPTION, wp_generate_password(64, true, true), '', false);
        }
    }

    public static function admin_menu() {
        add_submenu_page(
            'woocommerce',
            'Supply Bridge',
            'Supply Bridge',
            'manage_woocommerce',
            'bendemen-supply-bridge',
            [__CLASS__, 'settings_page']
        );
    }

    public static function register_settings() {
        register_setting('bendemen_supply_bridge', self::OPTION, [
            'type' => 'string',
            'sanitize_callback' => function ($value) {
                $value = trim((string) $value);
                return strlen($value) >= 40 ? $value : get_option(self::OPTION, '');
            },
        ]);
    }

    public static function settings_page() {
        if (!current_user_can('manage_woocommerce')) return;
        $secret = (string) get_option(self::OPTION, '');
        ?>
        <div class="wrap">
            <h1>Bendemen Supply Bridge</h1>
            <p>Deze sleutel koppelt Supply Panel veilig aan WooCommerce. Bewaar hem als <code>WC_BRIDGE_SECRET</code> in de omgeving van Supply Panel. Deel de sleutel niet.</p>
            <form method="post" action="options.php">
                <?php settings_fields('bendemen_supply_bridge'); ?>
                <table class="form-table"><tr>
                    <th scope="row"><label for="<?php echo esc_attr(self::OPTION); ?>">Gedeelde geheime sleutel</label></th>
                    <td><input type="password" autocomplete="new-password" class="regular-text" id="<?php echo esc_attr(self::OPTION); ?>" name="<?php echo esc_attr(self::OPTION); ?>" value="<?php echo esc_attr($secret); ?>" minlength="40" required>
                    <p class="description">Minimaal 40 tekens. De huidige sleutel is automatisch aangemaakt bij activatie.</p></td>
                </tr></table>
                <?php submit_button('Sleutel opslaan'); ?>
            </form>
            <p><strong>Status:</strong> <?php echo $secret ? '<span style="color:green">Sleutel ingesteld</span>' : '<span style="color:#b32d2e">Niet ingesteld</span>'; ?></p>
            <p><strong>Endpoint:</strong> <code><?php echo esc_html(rest_url(self::REST_NS . '/')); ?></code></p>
        </div>
        <?php
    }

    private static function authorized($request) {
        if (!class_exists('WooCommerce')) return new WP_Error('bendemen_wc_missing', 'WooCommerce is niet actief.', ['status' => 503]);
        $expected = (string) get_option(self::OPTION, '');
        $provided = (string) $request->get_header('x-bendemen-supply-key');
        if (!$expected || !$provided || !hash_equals($expected, $provided)) {
            return new WP_Error('bendemen_unauthorized', 'Ongeldige Supply Bridge-sleutel.', ['status' => 401]);
        }
        return true;
    }

    public static function register_routes() {
        $permission = [__CLASS__, 'authorized'];
        register_rest_route(self::REST_NS, '/products', [
            'methods' => 'GET', 'callback' => [__CLASS__, 'products'], 'permission_callback' => $permission,
        ]);
        register_rest_route(self::REST_NS, '/customers', [
            'methods' => 'GET', 'callback' => [__CLASS__, 'customers'], 'permission_callback' => $permission,
        ]);
        register_rest_route(self::REST_NS, '/customers/(?P<id>\d+)', [
            [
                'methods' => 'GET', 'callback' => [__CLASS__, 'customer'], 'permission_callback' => $permission,
            ],
            [
                'methods' => 'PUT,POST', 'callback' => [__CLASS__, 'update_customer'], 'permission_callback' => $permission,
            ],
        ]);
        register_rest_route(self::REST_NS, '/orders', [
            'methods' => 'POST', 'callback' => [__CLASS__, 'create_order'], 'permission_callback' => $permission,
        ]);
        register_rest_route(self::REST_NS, '/orders/(?P<id>\d+)', [
            [
                'methods' => 'GET', 'callback' => [__CLASS__, 'order'], 'permission_callback' => $permission,
            ],
            [
                'methods' => 'PUT,POST', 'callback' => [__CLASS__, 'update_order'], 'permission_callback' => $permission,
            ],
        ]);
    }

    public static function products($request) {
        $page = max(1, absint($request->get_param('page')));
        $per_page = min(100, max(1, absint($request->get_param('per_page')) ?: 100));
        $args = [
            'status' => ['publish', 'private', 'draft', 'pending', 'future'],
            'limit' => $per_page, 'page' => $page, 'return' => 'objects',
            'orderby' => 'ID', 'order' => 'ASC',
        ];
        $products = wc_get_products($args);
        return array_map([__CLASS__, 'format_product'], $products);
    }

    private static function format_product($product) {
        return [
            'id' => $product->get_id(),
            'name' => $product->get_name(),
            'type' => $product->get_type(),
            'status' => $product->get_status(),
            'sku' => $product->get_sku(),
            'price' => $product->get_price(),
            'regular_price' => $product->get_regular_price(),
            'sale_price' => $product->get_sale_price(),
            'description' => $product->get_description(),
            'short_description' => $product->get_short_description(),
            'stock_status' => $product->get_stock_status(),
            'categories' => array_map(function ($term) { return ['id' => $term->term_id, 'name' => $term->name, 'slug' => $term->slug]; }, $product->get_category_ids() ? get_terms(['taxonomy' => 'product_cat', 'include' => $product->get_category_ids(), 'hide_empty' => false]) : []),
            'meta_data' => self::public_meta($product->get_id()),
        ];
    }

    private static function public_meta($post_id) {
        $excluded = ['_edit_lock', '_edit_last'];
        $result = [];
        foreach (get_post_meta($post_id) as $key => $values) {
            if (str_starts_with($key, '_') || in_array($key, $excluded, true) || stripos($key, 'rank_math') === 0) continue;
            $value = maybe_unserialize($values[0] ?? '');
            $result[] = ['key' => $key, 'value' => $value];
        }
        return $result;
    }

    public static function customers($request) {
        $search = sanitize_text_field((string) $request->get_param('search'));
        $page = max(1, absint($request->get_param('page')));
        $users = get_users([
            'search' => $search ? '*' . $search . '*' : '',
            'search_columns' => ['user_email', 'user_login', 'display_name'],
            'number' => 30, 'paged' => $page, 'role__in' => ['customer', 'subscriber'],
        ]);
        return array_map([__CLASS__, 'format_customer'], $users);
    }

    public static function customer($request) {
        $user = get_user_by('id', absint($request['id']));
        if (!$user) return new WP_Error('bendemen_customer_missing', 'Klant niet gevonden.', ['status' => 404]);
        return self::format_customer($user);
    }

    private static function format_customer($user) {
        $billing_keys = ['first_name','last_name','company','address_1','address_2','city','state','postcode','country','email','phone'];
        $billing = [];
        foreach ($billing_keys as $key) $billing[$key] = (string) get_user_meta($user->ID, 'billing_' . $key, true);
        if (!$billing['email']) $billing['email'] = $user->user_email;
        return [
            'id' => (int) $user->ID, 'email' => $user->user_email,
            'first_name' => (string) get_user_meta($user->ID, 'first_name', true),
            'last_name' => (string) get_user_meta($user->ID, 'last_name', true),
            'username' => $user->user_login, 'billing' => $billing,
        ];
    }

    public static function update_customer($request) {
        $user_id = absint($request['id']);
        if (!get_user_by('id', $user_id)) return new WP_Error('bendemen_customer_missing', 'Klant niet gevonden.', ['status' => 404]);
        $billing = (array) $request->get_param('billing');
        $allowed = ['first_name','last_name','company','address_1','address_2','city','state','postcode','country','phone'];
        foreach ($allowed as $key) if (array_key_exists($key, $billing)) update_user_meta($user_id, 'billing_' . $key, sanitize_text_field((string) $billing[$key]));
        return self::customer(new WP_REST_Request('GET', '/'));
    }

    private static function find_order($id) {
        return wc_get_order(absint($id));
    }

    public static function order($request) {
        $order = self::find_order($request['id']);
        if (!$order) return new WP_Error('bendemen_order_missing', 'Bestelling niet gevonden.', ['status' => 404]);
        return self::format_order($order);
    }

    private static function format_order($order) {
        $items = [];
        foreach ($order->get_items('line_item') as $item) {
            $items[] = [
                'id' => $item->get_id(), 'name' => $item->get_name(),
                'product_id' => $item->get_product_id(), 'variation_id' => $item->get_variation_id(),
                'quantity' => $item->get_quantity(), 'subtotal' => $item->get_subtotal(),
                'total' => $item->get_total(), 'meta_data' => [],
            ];
        }
        $fees = [];
        foreach ($order->get_items('fee') as $item) $fees[] = ['id' => $item->get_id(), 'name' => $item->get_name(), 'total' => $item->get_total()];
        $billing = [];
        foreach (['first_name','last_name','company','address_1','address_2','city','state','postcode','country','email','phone'] as $key) $billing[$key] = $order->get_billing_ . $key;
        $billing = [
            'first_name'=>$order->get_billing_first_name(), 'last_name'=>$order->get_billing_last_name(),
            'company'=>$order->get_billing_company(), 'address_1'=>$order->get_billing_address_1(),
            'address_2'=>$order->get_billing_address_2(), 'city'=>$order->get_billing_city(),
            'state'=>$order->get_billing_state(), 'postcode'=>$order->get_billing_postcode(),
            'country'=>$order->get_billing_country(), 'email'=>$order->get_billing_email(),
            'phone'=>$order->get_billing_phone(),
        ];
        $meta = [];
        foreach ($order->get_meta_data() as $entry) {
            $data = $entry->get_data();
            $meta[] = ['key' => $data['key'], 'value' => $data['value']];
        }
        return [
            'id'=>$order->get_id(), 'number'=>$order->get_order_number(), 'status'=>$order->get_status(),
            'customer_id'=>$order->get_customer_id(), 'billing'=>$billing,
            'line_items'=>$items, 'fee_lines'=>$fees, 'total'=>$order->get_total(),
            'date_created'=>$order->get_date_created() ? $order->get_date_created()->date('c') : null,
            'date_paid'=>$order->get_date_paid() ? $order->get_date_paid()->date('c') : null,
            'meta_data'=>$meta,
        ];
    }

    private static function set_meta($object, $meta) {
        foreach ((array) $meta as $entry) {
            if (!isset($entry['key'])) continue;
            $object->update_meta_data(sanitize_key($entry['key']), $entry['value'] ?? '');
        }
    }

    private static function set_billing($order, $billing) {
        $map = ['first_name'=>'first_name','last_name'=>'last_name','company'=>'company','address_1'=>'address_1','address_2'=>'address_2','city'=>'city','state'=>'state','postcode'=>'postcode','country'=>'country','email'=>'email','phone'=>'phone'];
        foreach ($map as $key=>$method) if (array_key_exists($key, (array) $billing)) $order->{'set_billing_' . $method}(sanitize_text_field((string) $billing[$key]));
    }

    private static function set_lines($order, $payload, $type) {
        $existing = $type === 'fee' ? $order->get_items('fee') : $order->get_items('line_item');
        $keep = [];
        foreach ((array) $payload as $line) {
            $line_id = absint($line['id'] ?? 0);
            $item = $line_id && isset($existing[$line_id]) ? $existing[$line_id] : null;
            if (!empty($line['delete']) || ($type === 'line_item' && isset($line['quantity']) && (float) $line['quantity'] <= 0)) {
                if ($item) $order->remove_item($line_id);
                continue;
            }
            if ($type === 'fee') {
                if (!$item) $item = new WC_Order_Item_Fee();
                $item->set_name(sanitize_text_field($line['name'] ?? 'Supply Panel kosten'));
                $item->set_tax_status('none');
                $item->set_amount((float) ($line['total'] ?? 0));
                $item->set_total((float) ($line['total'] ?? 0));
            } else {
                if (!$item) $item = new WC_Order_Item_Product();
                $product_id = absint($line['product_id'] ?? 0);
                if ($product_id) $item->set_product(wc_get_product($product_id));
                $item->set_name(sanitize_text_field($line['name'] ?? 'Product'));
                $item->set_quantity(max(0, (float) ($line['quantity'] ?? 1)));
                $item->set_subtotal((float) ($line['subtotal'] ?? $line['total'] ?? 0));
                $item->set_total((float) ($line['total'] ?? 0));
            }
            $order->add_item($item);
            $keep[] = $item;
        }
    }

    private static function create_or_update($request, $existing = null) {
        $data = (array) $request->get_json_params();
        $order = $existing ?: wc_create_order(['customer_id' => absint($data['customer_id'] ?? 0)]);
        if (is_wp_error($order)) return $order;
        if (isset($data['customer_id'])) $order->set_customer_id(absint($data['customer_id']));
        if (isset($data['status'])) $order->set_status(sanitize_key($data['status']));
        if (isset($data['billing'])) self::set_billing($order, $data['billing']);
        if (isset($data['line_items'])) self::set_lines($order, $data['line_items'], 'product');
        if (isset($data['fee_lines'])) self::set_lines($order, $data['fee_lines'], 'fee');
        if (isset($data['meta_data'])) self::set_meta($order, $data['meta_data']);
        $order->calculate_totals(false);
        $order->save();
        return self::format_order($order);
    }

    public static function create_order($request) { return self::create_or_update($request); }

    public static function update_order($request) {
        $order = self::find_order($request['id']);
        if (!$order) return new WP_Error('bendemen_order_missing', 'Bestelling niet gevonden.', ['status' => 404]);
        return self::create_or_update($request, $order);
    }
}

Bendemen_Supply_Bridge::boot();

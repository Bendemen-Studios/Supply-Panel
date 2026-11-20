# Bendemen Supply Bridge

Interne WordPress-plugin voor de verbinding tussen WooCommerce en Bendemen Supply Panel.

## Installeren op studios.bendemen.com

1. Upload de map `Bendemen-Supply-Bridge` naar `wp-content/plugins/` (of zip deze map en upload via Plugins → Nieuwe plugin → Plugin uploaden).
2. Activeer **Bendemen Supply Bridge** in WordPress.
3. Open WooCommerce → Supply Bridge.
4. Kopieer de gedeelde geheime sleutel naar de omgeving van Supply Panel als `WC_BRIDGE_SECRET`.
5. Controleer dat `WC_STORE_URL` naar `https://studios.bendemen.com` verwijst.
6. Herstart Supply Panel.

De plugin maakt bij activatie automatisch een willekeurige sleutel aan. De API accepteert alleen verzoeken met de header `X-Bendemen-Supply-Key`. Gebruik HTTPS en deel de sleutel niet.

## Beschikbare endpoints

- `GET /wp-json/bendemen-supply/v1/products`
- `GET /wp-json/bendemen-supply/v1/customers?search=...`
- `GET /wp-json/bendemen-supply/v1/customers/{id}`
- `PUT /wp-json/bendemen-supply/v1/customers/{id}`
- `POST /wp-json/bendemen-supply/v1/orders`
- `GET /wp-json/bendemen-supply/v1/orders/{id}`
- `PUT /wp-json/bendemen-supply/v1/orders/{id}`

De factuur-PDF-integratie blijft voorlopig via de bestaande afzonderlijke Invoice Bridge lopen en gebruikt `WPO_WCPDF_API_TOKEN`.

## Belangrijk

De Supply Panel-client is voorbereid op deze bridge en gebruikt niet langer de WooCommerce REST API-authenticatie met consumer key/secret. De plugin moet eerst op WordPress zijn geïnstalleerd en de geheime sleutel moet in Supply Panel zijn ingesteld voordat WooCommerce-synchronisatie weer werkt.

Supply Panel-abonnementen blijven de bestaande lokale recurring-orders-functionaliteit gebruiken. Deze plugin vereist geen WooCommerce Subscriptions-extensie.

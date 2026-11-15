# WooCommerce SSO bridge

De plugin staat in `wordpress-plugin/bendemen-supply-sso/`. Installeer de map als plugin op de WordPress-site (Cloud86) en activeer **Bendemen Supply Panel SSO**.

## 1. Gedeeld geheim aanmaken

Genereer één willekeurige sleutel van minimaal 32 tekens, bijvoorbeeld met:

```bash
openssl rand -hex 32
```

Gebruik exact dezelfde sleutel aan beide kanten. Deel deze sleutel niet via GitHub en commit hem nooit.

## 2. WordPress / Cloud86

Voeg in `wp-config.php`, boven de regel `/* That's all, stop editing! */`, toe:

```php
define('BENDEMEN_SUPPLY_SSO_SECRET', 'VUL_HIER_HET_GEHEIM_IN');
```

## 3. Supply Panel / Pterodactyl

Voeg aan de environment toe:

```env
WC_SSO_URL=https://jouw-webshop-domein.nl
WC_SSO_SECRET=HETZELFDE_GEHEIM
```

Gebruik als `WC_SSO_URL` de basis-URL van WordPress, zonder afsluitende slash. Herstart daarna Supply Panel.

## Werking en beveiliging

- Alleen een ingelogde Supply Panel-klant kan een SSO-betaallink voor zijn eigen lokale bestelling aanvragen.
- Supply Panel ondertekent een payload met HMAC-SHA256; de payload bevat alleen WooCommerce-order-ID, WooCommerce-klant-ID, een willekeurige nonce en een vervaltijd van 90 seconden.
- WordPress controleert de handtekening, vervaltijd, nonce, klantkoppeling en of de bestelling nog betaling nodig heeft.
- De plugin maakt een WordPress-login aan voor de bestaande WooCommerce-klant en stuurt door naar de officiële WooCommerce-betaalpagina.
- Als SSO niet is geconfigureerd of de bestelling geen gekoppelde WooCommerce-klant heeft, blijft Supply Panel de bestaande betaallink gebruiken.

## Testen

1. Activeer de plugin en stel beide geheimen in.
2. Controleer dat de WooCommerce-klant-ID in Supply Panel overeenkomt met de WordPress-gebruiker-ID.
3. Log in op Supply Panel als die klant en open een openstaande bestelling.
4. Klik op **Nu betalen**. Je hoort zonder tweede login op de WooCommerce-betaalpagina uit te komen.
5. Herhaal met een andere klant en controleer dat die niet bij andermans bestelling kan komen.

Gebruik uitsluitend HTTPS op beide sites. Als SSO niet werkt, controleer de WordPress/PHP-foutlogs en de Supply Panel-omgeving. Schakel de SSO-variabelen tijdelijk uit om terug te vallen op de bestaande betaallink.

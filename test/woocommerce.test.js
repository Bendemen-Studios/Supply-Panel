"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isWooProductId } = require("../src/woocommerce");

test("WooCommerce product IDs accept numeric IDs only", () => {
  assert.equal(isWooProductId("123"), true);
  assert.equal(isWooProductId(123), true);
  assert.equal(isWooProductId("local:123"), false);
  assert.equal(isWooProductId(""), false);
  assert.equal(isWooProductId("12x"), false);
});

test("local catalog products become WooCommerce product line items, not fee lines", () => {
  const line = require("../src/woocommerce").buildWooLineItem({
    product_id: "local:123",
    product_name: "Productie - 3D Print",
    quantity: 50,
    unit_price_cents: 335,
    meta_data: "[]"
  });
  assert.equal(line.name, "Productie - 3D Print");
  assert.equal(line.quantity, 50);
  assert.equal(line.subtotal, "167.50");
  assert.equal(line.total, "167.50");
  assert.equal("product_id" in line, false);
  assert.equal("tax_status" in line, false);
});
